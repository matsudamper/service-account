package net.matsudamper.serviceaccount.grpc

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import io.grpc.Status
import io.grpc.StatusException
import net.matsudamper.serviceaccount.client.RegisteredClient
import net.matsudamper.serviceaccount.db.PasskeyDeleteResult
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.logic.AuthenticatedUser
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordService
import net.matsudamper.serviceaccount.logic.SessionService
import net.matsudamper.serviceaccount.proto.v1.AccountServiceGrpcKt
import net.matsudamper.serviceaccount.proto.v1.ChangePasswordError
import net.matsudamper.serviceaccount.proto.v1.ChangePasswordRequest
import net.matsudamper.serviceaccount.proto.v1.ChangePasswordResponse
import net.matsudamper.serviceaccount.proto.v1.CreatePasskeyRegistrationOptionsRequest
import net.matsudamper.serviceaccount.proto.v1.CreatePasskeyRegistrationOptionsResponse
import net.matsudamper.serviceaccount.proto.v1.DeletePasskeyRequest
import net.matsudamper.serviceaccount.proto.v1.DeletePasskeyResponse
import net.matsudamper.serviceaccount.proto.v1.DeletePasskeyResult
import net.matsudamper.serviceaccount.proto.v1.DeletePasswordRequest
import net.matsudamper.serviceaccount.proto.v1.DeletePasswordResponse
import net.matsudamper.serviceaccount.proto.v1.DeletePasswordResult
import net.matsudamper.serviceaccount.proto.v1.DeleteSessionRequest
import net.matsudamper.serviceaccount.proto.v1.DeleteSessionResponse
import net.matsudamper.serviceaccount.proto.v1.DeleteSessionResult
import net.matsudamper.serviceaccount.proto.v1.GetAccountRequest
import net.matsudamper.serviceaccount.proto.v1.GetAccountResponse
import net.matsudamper.serviceaccount.proto.v1.ListPasskeysRequest
import net.matsudamper.serviceaccount.proto.v1.ListPasskeysResponse
import net.matsudamper.serviceaccount.proto.v1.ListSessionsRequest
import net.matsudamper.serviceaccount.proto.v1.ListSessionsResponse
import net.matsudamper.serviceaccount.proto.v1.RegisterPasskeyRequest
import net.matsudamper.serviceaccount.proto.v1.RegisterPasskeyResponse
import net.matsudamper.serviceaccount.proto.v1.RegisterPasskeyResult
import net.matsudamper.serviceaccount.proto.v1.RenameSessionRequest
import net.matsudamper.serviceaccount.proto.v1.RenameSessionResponse
import net.matsudamper.serviceaccount.proto.v1.RenameSessionResult
import net.matsudamper.serviceaccount.proto.v1.changePasswordResponse
import net.matsudamper.serviceaccount.proto.v1.createPasskeyRegistrationOptionsResponse
import net.matsudamper.serviceaccount.proto.v1.deletePasskeyResponse
import net.matsudamper.serviceaccount.proto.v1.deletePasswordResponse
import net.matsudamper.serviceaccount.proto.v1.deleteSessionResponse
import net.matsudamper.serviceaccount.proto.v1.getAccountResponse
import net.matsudamper.serviceaccount.proto.v1.listPasskeysResponse
import net.matsudamper.serviceaccount.proto.v1.listSessionsResponse
import net.matsudamper.serviceaccount.proto.v1.passkey
import net.matsudamper.serviceaccount.proto.v1.registerPasskeyResponse
import net.matsudamper.serviceaccount.proto.v1.renameSessionResponse
import net.matsudamper.serviceaccount.proto.v1.session

class AccountGrpcService(
    private val userRepository: UserRepository,
    private val passwordService: PasswordService,
    private val passkeyService: PasskeyService,
    private val sessionService: SessionService,
    private val ioContext: CoroutineContext = Dispatchers.IO,
) : AccountServiceGrpcKt.AccountServiceCoroutineImplBase() {
    override suspend fun getAccount(request: GetAccountRequest): GetAccountResponse =
        authenticated(request.accessToken) { _, user ->
            getAccountResponse {
                userId = user.userId.value
                username = user.username
                hasPassword = passwordService.hasPassword(user.userId)
            }
        }

    override suspend fun changePassword(request: ChangePasswordRequest): ChangePasswordResponse =
        authenticated(request.accessToken) { _, user ->
            val violations = passwordService.change(userId = user.userId, newPassword = request.newPassword)
            changePasswordResponse {
                if (violations.invalidLength) errors += ChangePasswordError.CHANGE_PASSWORD_ERROR_LENGTH
                if (violations.invalidCharacters.isNotEmpty()) errors += ChangePasswordError.CHANGE_PASSWORD_ERROR_INVALID_CHARACTER
                invalidCharacters = violations.invalidCharacters
            }
        }

    override suspend fun deletePassword(request: DeletePasswordRequest): DeletePasswordResponse =
        authenticated(request.accessToken) { _, user ->
            deletePasswordResponse {
                result =
                    when (passwordService.delete(user.userId)) {
                        PasswordService.DeletePasswordResult.Success -> DeletePasswordResult.DELETE_PASSWORD_RESULT_SUCCESS
                        PasswordService.DeletePasswordResult.NoPasskey -> DeletePasswordResult.DELETE_PASSWORD_RESULT_NO_PASSKEY
                    }
            }
        }

    override suspend fun createPasskeyRegistrationOptions(request: CreatePasskeyRegistrationOptionsRequest): CreatePasskeyRegistrationOptionsResponse =
        authenticated(request.accessToken) { client, user ->
            val storedUser = userRepository.findById(user.userId) ?: throw StatusException(Status.UNAUTHENTICATED)
            createPasskeyRegistrationOptionsResponse { optionsJson = passkeyService.registrationOptions(client = client, user = storedUser) }
        }

    override suspend fun registerPasskey(request: RegisterPasskeyRequest): RegisterPasskeyResponse =
        authenticated(request.accessToken) { client, user ->
            val result = passkeyService.register(client = client, userId = user.userId, name = request.name, credentialJson = request.credentialJson)
            registerPasskeyResponse {
                this.result =
                    when (result) {
                        PasskeyService.RegistrationResult.Success -> RegisterPasskeyResult.REGISTER_PASSKEY_RESULT_SUCCESS
                        PasskeyService.RegistrationResult.NotAccepted -> RegisterPasskeyResult.REGISTER_PASSKEY_RESULT_NOT_ACCEPTED
                        PasskeyService.RegistrationResult.AlreadyRegistered -> RegisterPasskeyResult.REGISTER_PASSKEY_RESULT_ALREADY_REGISTERED
                        PasskeyService.RegistrationResult.InvalidName -> RegisterPasskeyResult.REGISTER_PASSKEY_RESULT_INVALID_NAME
                    }
            }
        }

    override suspend fun listPasskeys(request: ListPasskeysRequest): ListPasskeysResponse =
        authenticated(request.accessToken) { _, user ->
            listPasskeysResponse {
                passkeyService.passkeys(user.userId).forEach { summary ->
                    passkeys +=
                        passkey {
                            id = summary.credentialId
                            name = summary.name
                            rpId = summary.rpId
                            createdAtEpochMillis = summary.createdAt.toEpochMilli()
                            summary.lastUsedAt?.let { lastUsedAtEpochMillis = it.toEpochMilli() }
                        }
                }
            }
        }

    override suspend fun deletePasskey(request: DeletePasskeyRequest): DeletePasskeyResponse =
        authenticated(request.accessToken) { _, user ->
            deletePasskeyResponse {
                result =
                    when (passkeyService.delete(userId = user.userId, credentialId = request.passkeyId)) {
                        PasskeyDeleteResult.Success -> DeletePasskeyResult.DELETE_PASSKEY_RESULT_SUCCESS
                        PasskeyDeleteResult.NotFound -> DeletePasskeyResult.DELETE_PASSKEY_RESULT_NOT_FOUND
                        PasskeyDeleteResult.LastLoginMethod -> DeletePasskeyResult.DELETE_PASSKEY_RESULT_LAST_LOGIN_METHOD
                    }
            }
        }

    override suspend fun listSessions(request: ListSessionsRequest): ListSessionsResponse =
        authenticated(request.accessToken) { _, user ->
            listSessionsResponse {
                sessionService.sessions(user.userId).forEach { stored ->
                    sessions +=
                        session {
                            id = stored.sessionId
                            name = stored.name
                            clientId = stored.clientId
                            createdAtEpochMillis = stored.createdAt.toEpochMilli()
                            lastUsedAtEpochMillis = stored.lastUsedAt.toEpochMilli()
                            expiresAtEpochMillis = stored.expiresAt.toEpochMilli()
                            current = stored.sessionId == user.sessionId
                        }
                }
            }
        }

    override suspend fun deleteSession(request: DeleteSessionRequest): DeleteSessionResponse =
        authenticated(request.accessToken) { _, user ->
            deleteSessionResponse {
                result =
                    if (sessionService.delete(userId = user.userId, sessionId = request.sessionId)) {
                        DeleteSessionResult.DELETE_SESSION_RESULT_SUCCESS
                    } else {
                        DeleteSessionResult.DELETE_SESSION_RESULT_NOT_FOUND
                    }
            }
        }

    override suspend fun renameSession(request: RenameSessionRequest): RenameSessionResponse =
        authenticated(request.accessToken) { _, user ->
            renameSessionResponse {
                result =
                    when (sessionService.rename(userId = user.userId, sessionId = request.sessionId, name = request.name)) {
                        SessionService.RenameResult.Success -> RenameSessionResult.RENAME_SESSION_RESULT_SUCCESS
                        SessionService.RenameResult.NotFound -> RenameSessionResult.RENAME_SESSION_RESULT_NOT_FOUND
                        SessionService.RenameResult.InvalidName -> RenameSessionResult.RENAME_SESSION_RESULT_INVALID_NAME
                    }
            }
        }

    private suspend fun <T> authenticated(
        accessToken: String,
        block: suspend CoroutineScope.(RegisteredClient, AuthenticatedUser) -> T,
    ): T {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            val user =
                sessionService.authenticate(accessToken = accessToken, clientId = client.id)
                    ?: throw StatusException(Status.UNAUTHENTICATED.withDescription("アクセストークンが通らない"))
            block(client, user)
        }
    }
}
