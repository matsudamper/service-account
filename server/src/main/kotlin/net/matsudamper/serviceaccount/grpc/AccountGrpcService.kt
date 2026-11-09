package net.matsudamper.serviceaccount.grpc

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import io.grpc.Status
import io.grpc.StatusException
import net.matsudamper.serviceaccount.client.RegisteredClient
import net.matsudamper.serviceaccount.db.PasskeyDeleteResult
import net.matsudamper.serviceaccount.db.User
import net.matsudamper.serviceaccount.db.UserId
import net.matsudamper.serviceaccount.db.UserRepository
import net.matsudamper.serviceaccount.logic.PasskeyService
import net.matsudamper.serviceaccount.logic.PasswordService
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
import net.matsudamper.serviceaccount.proto.v1.GetAccountRequest
import net.matsudamper.serviceaccount.proto.v1.GetAccountResponse
import net.matsudamper.serviceaccount.proto.v1.ListPasskeysRequest
import net.matsudamper.serviceaccount.proto.v1.ListPasskeysResponse
import net.matsudamper.serviceaccount.proto.v1.RegisterPasskeyRequest
import net.matsudamper.serviceaccount.proto.v1.RegisterPasskeyResponse
import net.matsudamper.serviceaccount.proto.v1.RegisterPasskeyResult
import net.matsudamper.serviceaccount.proto.v1.changePasswordResponse
import net.matsudamper.serviceaccount.proto.v1.createPasskeyRegistrationOptionsResponse
import net.matsudamper.serviceaccount.proto.v1.deletePasskeyResponse
import net.matsudamper.serviceaccount.proto.v1.deletePasswordResponse
import net.matsudamper.serviceaccount.proto.v1.getAccountResponse
import net.matsudamper.serviceaccount.proto.v1.listPasskeysResponse
import net.matsudamper.serviceaccount.proto.v1.passkey
import net.matsudamper.serviceaccount.proto.v1.registerPasskeyResponse

class AccountGrpcService(
    private val userRepository: UserRepository,
    private val passwordService: PasswordService,
    private val passkeyService: PasskeyService,
    private val ioContext: CoroutineContext = Dispatchers.IO,
) : AccountServiceGrpcKt.AccountServiceCoroutineImplBase() {
    override suspend fun getAccount(request: GetAccountRequest): GetAccountResponse =
        withUser(request.userId) { _, user ->
            getAccountResponse {
                userId = user.id.value
                username = user.username
                hasPassword = passwordService.hasPassword(user.id)
            }
        }

    override suspend fun changePassword(request: ChangePasswordRequest): ChangePasswordResponse =
        withUser(request.userId) { _, user ->
            val violations = passwordService.change(userId = user.id, newPassword = request.newPassword)
            changePasswordResponse {
                if (violations.invalidLength) errors += ChangePasswordError.CHANGE_PASSWORD_ERROR_LENGTH
                if (violations.invalidCharacters.isNotEmpty()) errors += ChangePasswordError.CHANGE_PASSWORD_ERROR_INVALID_CHARACTER
                invalidCharacters = violations.invalidCharacters
            }
        }

    override suspend fun deletePassword(request: DeletePasswordRequest): DeletePasswordResponse =
        withUser(request.userId) { _, user ->
            deletePasswordResponse {
                result =
                    when (passwordService.delete(user.id)) {
                        PasswordService.DeletePasswordResult.Success -> DeletePasswordResult.DELETE_PASSWORD_RESULT_SUCCESS
                        PasswordService.DeletePasswordResult.NoPasskey -> DeletePasswordResult.DELETE_PASSWORD_RESULT_NO_PASSKEY
                    }
            }
        }

    override suspend fun createPasskeyRegistrationOptions(request: CreatePasskeyRegistrationOptionsRequest): CreatePasskeyRegistrationOptionsResponse =
        withUser(request.userId) { client, user ->
            createPasskeyRegistrationOptionsResponse { optionsJson = passkeyService.registrationOptions(client = client, user = user) }
        }

    override suspend fun registerPasskey(request: RegisterPasskeyRequest): RegisterPasskeyResponse =
        withUser(request.userId) { client, user ->
            val result = passkeyService.register(client = client, userId = user.id, name = request.name, credentialJson = request.credentialJson)
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
        withUser(request.userId) { _, user ->
            listPasskeysResponse {
                passkeyService.passkeys(user.id).forEach { summary ->
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
        withUser(request.userId) { _, user ->
            deletePasskeyResponse {
                result =
                    when (passkeyService.delete(userId = user.id, credentialId = request.passkeyId)) {
                        PasskeyDeleteResult.Success -> DeletePasskeyResult.DELETE_PASSKEY_RESULT_SUCCESS
                        PasskeyDeleteResult.NotFound -> DeletePasskeyResult.DELETE_PASSKEY_RESULT_NOT_FOUND
                        PasskeyDeleteResult.LastLoginMethod -> DeletePasskeyResult.DELETE_PASSKEY_RESULT_LAST_LOGIN_METHOD
                    }
            }
        }

    private suspend fun <T> withUser(
        userId: Long,
        block: suspend CoroutineScope.(RegisteredClient, User) -> T,
    ): T {
        val client = ClientAuthInterceptor.currentClient()
        return withContext(ioContext) {
            val user =
                userRepository.findById(UserId(userId))
                    ?: throw StatusException(Status.NOT_FOUND.withDescription("ユーザーがいない"))
            block(client, user)
        }
    }
}
