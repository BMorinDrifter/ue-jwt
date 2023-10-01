#include "UeJwt.h"
#include "Json.h"
#include "Misc/Base64.h"

// Work around a conflict between a UI namespace defined by engine code and a typedef in OpenSSL
#define UI UI_ST
// Work around assertion macros in ue4
#undef verify 
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#undef UI

#include <memory>
#include <string>

// Base64Url encoding replaces '+' and '/' with '-' and '_' respectively.
// The JWT spec calls for no '=' padding at the end

FString Base64UrlEncode(const TArray<uint8>& source)
{
	FString b64 = FBase64::Encode(source);
	b64.ReplaceCharInline(TCHAR('+'), TCHAR('-'), ESearchCase::CaseSensitive);
	b64.ReplaceCharInline(TCHAR('/'), TCHAR('_'), ESearchCase::CaseSensitive);
	while (!b64.IsEmpty() && b64[b64.Len() - 1] == '=') {
		b64.RemoveAt(b64.Len() - 1);
	}
	return b64;
}

FString Base64UrlEncode(const FString& source)
{
	FString b64 = FBase64::Encode(source);
	b64.ReplaceCharInline(TCHAR('+'), TCHAR('-'), ESearchCase::CaseSensitive);
	b64.ReplaceCharInline(TCHAR('/'), TCHAR('_'), ESearchCase::CaseSensitive);
	while (!b64.IsEmpty() && b64[b64.Len() - 1] == '=') {
		b64.RemoveAt(b64.Len() - 1);
	}
	return b64;
}

bool Base64UrlDecode(FString& source, TArray<uint8>& dest)
{
	// source is mutated to avoid a memory copy
	source.ReplaceCharInline(TCHAR('-'), TCHAR('+'), ESearchCase::CaseSensitive);
	source.ReplaceCharInline(TCHAR('_'), TCHAR('/'), ESearchCase::CaseSensitive);
	return FBase64::Decode(source, dest);
}

bool Base64UrlDecode(FString& source, FString& dest)
{
	// source is mutated to avoid a memory copy
	source.ReplaceCharInline(TCHAR('-'), TCHAR('+'), ESearchCase::CaseSensitive);
	source.ReplaceCharInline(TCHAR('_'), TCHAR('/'), ESearchCase::CaseSensitive);
	return FBase64::Decode(source, dest);
}

bool CheckSignatureRs256(const FString& publicKey, const FString& headerAndPayload, const TArray<uint8>& signature)
{
	const std::string key(TCHAR_TO_UTF8(*publicKey));
	const std::string data(TCHAR_TO_UTF8(*headerAndPayload));
	const auto hashAlgorithm = EVP_sha256;

	// Read the public key in PEM format

	std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
	if (!pubkey_bio) {
		return false;
	}

	const int len = static_cast<int>(key.size());
	if (BIO_write(pubkey_bio.get(), key.data(), len) != len) {
		return false;
	}

	std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
		PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, nullptr),
		EVP_PKEY_free);
	if (!pkey) {
		return false;
	}

	// Check the signature

	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
	if (!ctx) {
		return false;
	}

	if (!EVP_VerifyInit(ctx.get(), hashAlgorithm())) {
		return false;
	}
	if (!EVP_VerifyUpdate(ctx.get(), data.data(), data.size())) {
		return false;
	}
	auto res = EVP_VerifyFinal(ctx.get(), reinterpret_cast<const unsigned char*>(signature.GetData()),
		static_cast<unsigned int>(signature.Num()), pkey.get());
	if (res != 1) {
		return false;
	}

	return true;
}

bool GenerateSignatureRs256(const FString& privateKey, const FString& headerAndPayload, TArray<uint8>& signature)
{
	signature.Empty();

	const std::string key(TCHAR_TO_UTF8(*privateKey));
	const std::string data(TCHAR_TO_UTF8(*headerAndPayload));
	const std::string password;
	const auto hashAlgorithm = EVP_sha256;

	// Read the private key in PEM format

	std::unique_ptr<BIO, decltype(&BIO_free_all)> privkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
	if (!privkey_bio) {
		return false;
	}
	const int len = static_cast<int>(key.size());
	if (BIO_write(privkey_bio.get(), key.data(), len) != len) {
		return false;
	}
	std::shared_ptr<EVP_PKEY> pkey(
		PEM_read_bio_PrivateKey(privkey_bio.get(), nullptr, nullptr, const_cast<char*>(password.c_str())),
		EVP_PKEY_free);
	if (!pkey) {
		return false;
	}

	// generate the signature

	std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
	if (!ctx) {
		return false;
	}
	if (!EVP_SignInit(ctx.get(), hashAlgorithm())) {
		return false;
	}

	signature.Init(0, EVP_PKEY_size(pkey.get()));
	unsigned int size = 0;

	if (!EVP_SignUpdate(ctx.get(), data.data(), data.size())) {
		return false;
	}
	if (EVP_SignFinal(ctx.get(), const_cast<unsigned char*>(signature.GetData()), &size, pkey.get()) == 0) {
		return false;
	}

	signature.SetNum(size);

	return true;
}

bool UeJwt::CheckToken(
	const FString& token,
	const FString& publicKey, 
	const TMap<FString, TArray<FString>>& expectedClaims,
	int64 leeway,
	const FString& userIdPrefix, 
	FString& userId, 
	FString& displayName)
{
	userId.Empty();
	displayName.Empty();

	if (token.IsEmpty() || publicKey.IsEmpty()) {
		return false;
	}

	// JWT format is XXXX.XXXX.XXXX 
	// first block is the Base64 encoded json header
	// second block is the Base64 encoded json payload
	// third block is the Base64 encoded signature

	// Split this way first because we need to check the signature against headerAndPayload
	FString headerAndPayload;
	FString signatureBase64;
	if (!token.Split(TEXT("."), &headerAndPayload, &signatureBase64, ESearchCase::CaseSensitive, ESearchDir::FromEnd)) {
		UE_LOG(LogOnline, Warning, TEXT("Invalid JWT format"));
		return false;
	}

	FString headerBase64;
	FString payloadBase64;
	if (!headerAndPayload.Split(TEXT("."), &headerBase64, &payloadBase64, ESearchCase::CaseSensitive, ESearchDir::FromStart)) {
		UE_LOG(LogOnline, Warning, TEXT("Invalid JWT format"));
		return false;
	}

	FString header;
	FString payload;
	TArray<uint8> signature;
	if (!Base64UrlDecode(headerBase64, header)
	 || !Base64UrlDecode(payloadBase64, payload)
     || !Base64UrlDecode(signatureBase64, signature)) {
		UE_LOG(LogOnline, Warning, TEXT("Invalid JWT format"));
		return false;
	}

	//
	// Header
	// 

	TSharedPtr<FJsonObject> headerJson;
	{
		TSharedRef<TJsonReader<TCHAR>> reader = TJsonReaderFactory<TCHAR>::Create(header);
		if (!FJsonSerializer::Deserialize(reader, headerJson)) {
			UE_LOG(LogOnline, Warning, TEXT("Failed to Deserialize JWT header"));
			return false;
		}
	}

	FString typ;
	if (!headerJson->TryGetStringField("typ", typ) || typ != "JWT") {
		UE_LOG(LogOnline, Warning, TEXT("Missing or invalid typ in header"));
		return false;
	}

	FString alg;
	if (!headerJson->TryGetStringField("alg", alg)) {
		UE_LOG(LogOnline, Warning, TEXT("Missing alg in header"));
		return false;
	}

	if (alg != "RS256") {
		UE_LOG(LogOnline, Warning, TEXT("Unsupported alg %s"), *alg);
		return false;
	}

	//
	// Signature
	// 
	// Checking this next so we can skip the payload validation when going through different keys for a match
	// 

	if (!CheckSignatureRs256(publicKey, headerAndPayload, signature)) {
		UE_LOG(LogOnline, Verbose, TEXT("Signature check failed"));
		return false;
	}

	//
	// Payload
	// 

	TSharedPtr<FJsonObject> payloadJson;
	{
		TSharedRef<TJsonReader<TCHAR>> reader = TJsonReaderFactory<TCHAR>::Create(payload);
		if (!FJsonSerializer::Deserialize(reader, payloadJson)) {
			UE_LOG(LogOnline, Warning, TEXT("Failed to Deserialize JWT payload"));
			return false;
		}
	}

	// Check expected claims

	for (auto expectedClaim : expectedClaims) {
		FString claim;
		if (!payloadJson->TryGetStringField(expectedClaim.Key, claim)) {
			UE_LOG(LogOnline, Warning, TEXT("Missing claim %s"), *expectedClaim.Key);
			return false;
		}

		if (!expectedClaim.Value.Contains(claim)) {
			UE_LOG(LogOnline, Warning, TEXT("Claim %s has invalid value %s"), *expectedClaim.Key, *claim);
			return false;
		}
	}

	// Check the expiration

	int64 iat;
	if (!payloadJson->TryGetNumberField("iat", iat)) {
		UE_LOG(LogOnline, Warning, TEXT("Missing iat in payload"));
		return false;
	}

	int64 exp;
	if (!payloadJson->TryGetNumberField("exp", exp)) {
		UE_LOG(LogOnline, Warning, TEXT("Missing exp in payload"));
		exp = iat;
	}

	int64 now = FDateTime::UtcNow().ToUnixTimestamp();
	if (now - exp > leeway) {
		UE_LOG(LogOnline, Warning, TEXT("JWT expired"));
		return false;
	}

	// Extract the User Id and Display Name
	FString id;
	if (!payloadJson->TryGetStringField("id", id)) {
		if (!payloadJson->TryGetStringField("sub", id)) {
			UE_LOG(LogOnline, Warning, TEXT("User Id not found"));
			return false;
		}
	}
	userId = userIdPrefix + id;

	if (!payloadJson->TryGetStringField("displayName", displayName)) {
		if (!payloadJson->TryGetStringField("dn", displayName)) {
			UE_LOG(LogOnline, Warning, TEXT("Display Name not found"));
			return false;
		}
	}

	return true;
}
