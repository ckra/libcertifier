/**
 * Copyright 2021 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <CertifierOperationalCredentialsIssuer.h>

#include <stddef.h>

#include <controller/CommissioneeDeviceProxy.h>
#include <credentials/DeviceAttestationCredsProvider.h>
#include <lib/asn1/ASN1.h>
#include <lib/asn1/ASN1Macros.h>
#include <lib/core/CHIPTLV.h>
#include <lib/support/CHIPMem.h>
#include <lib/support/CodeUtils.h>
#include <lib/support/ScopedBuffer.h>
#include <lib/support/TestGroupData.h>
#include <lib/support/Base64.h>

#include <memory>
#include <string>
#include <cinttypes>
#include <iostream>
#include <iomanip>

#include <certifier/certifier_api_easy.h>
#include <certifier/certifier_api_easy_internal.h>
#include <certifier/certifier_internal.h>
#include <certifier/http.h>
#include <certifier/util.h>
#include <certifier/security.h>
#include <certifier/types.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>

namespace {

constexpr char cert_id[] = "X509";

}

namespace chip {
namespace Controller {

using namespace Credentials;
using namespace Crypto;
using namespace ASN1;
using namespace TLV;

CHIP_ERROR CertifierOperationalCredentialsIssuer::GenerateNOCChainAfterValidation(NodeId nodeId, FabricId fabricId,
                                                                                  const ByteSpan & dac, const ByteSpan & csr,
                                                                                  const ByteSpan & nonce, MutableByteSpan & rcac,
                                                                                  MutableByteSpan & icac, MutableByteSpan & noc)
{
    CHIP_ERROR error = CHIP_NO_ERROR;
    X509_LIST * certs;
    X509_CERT * cert = nullptr;
    unsigned char * rawCert = nullptr;
    size_t rawCertLength = 0;
    uint8_t OpCertificateChain[4096];
    MutableByteSpan OpCertificateChainSpan(OpCertificateChain);

    SuccessOrExit(error = ObtainOpCert(dac, csr, nonce, OpCertificateChainSpan, fabricId, nodeId));

    OpCertificateChain[OpCertificateChainSpan.size()] = 0;
    util_trim(reinterpret_cast<char *>(OpCertificateChain));

    security_load_certs_from_pem(reinterpret_cast<const char *>(OpCertificateChain), &certs);

    cert = security_cert_list_get(certs, 0);
    VerifyOrExit(cert != nullptr, error = CHIP_ERROR_INTERNAL);
    rawCert = security_X509_to_DER(cert, &rawCertLength);
    VerifyOrExit(rawCert != nullptr, error = CHIP_ERROR_INTERNAL);
    SuccessOrExit(error = CopySpanToMutableSpan(ByteSpan(rawCert, rawCertLength), noc));
    XFREE(rawCert);

    cert = security_cert_list_get(certs, 1);
    VerifyOrExit(cert != nullptr, error = CHIP_ERROR_INTERNAL);
    rawCert = security_X509_to_DER(cert, &rawCertLength);
    VerifyOrExit(rawCert != nullptr, error = CHIP_ERROR_INTERNAL);
    SuccessOrExit(error = CopySpanToMutableSpan(ByteSpan(rawCert, rawCertLength), icac));
    XFREE(rawCert);

    cert = security_cert_list_get(certs, 2);
    VerifyOrExit(cert != nullptr, error = CHIP_ERROR_INTERNAL);
    rawCert = security_X509_to_DER(cert, &rawCertLength);
    VerifyOrExit(rawCert != nullptr, error = CHIP_ERROR_INTERNAL);
    SuccessOrExit(error = CopySpanToMutableSpan(ByteSpan(rawCert, rawCertLength), rcac));

exit:
    XFREE(rawCert);
    security_free_cert_list(certs);

    return error;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::GenerateNOCChain(const ByteSpan & csrElements, const ByteSpan & csrNonce,
                                                                   const ByteSpan & attestationSignature,
                                                                   const ByteSpan & attestationChallenge, const ByteSpan & DAC,
                                                                   const ByteSpan & PAI,
                                                                   Callback::Callback<OnNOCChainGeneration> * onCompletion)
{
    ChipLogProgress(Controller, "Verifying Certificate Signing Request");
    TLVReader reader;
    reader.Init(csrElements);

    if (reader.GetType() == kTLVType_NotSpecified)
    {
        ReturnErrorOnFailure(reader.Next());
    }

    VerifyOrReturnError(reader.GetType() == kTLVType_Structure, CHIP_ERROR_WRONG_TLV_TYPE);
    VerifyOrReturnError(reader.GetTag() == AnonymousTag(), CHIP_ERROR_UNEXPECTED_TLV_ELEMENT);

    TLVType containerType;
    ReturnErrorOnFailure(reader.EnterContainer(containerType));
    ReturnErrorOnFailure(reader.Next(kTLVType_ByteString, TLV::ContextTag(1)));

    ByteSpan csr;
    ReturnErrorOnFailure(reader.Get(csr));

    ReturnErrorOnFailure(reader.Next(kTLVType_ByteString, TLV::ContextTag(2)));

    ByteSpan nonce;
    ReturnErrorOnFailure(reader.Get(nonce));

    reader.ExitContainer(containerType);

    Platform::ScopedMemoryBuffer<uint8_t> noc;
    ReturnErrorCodeIf(!noc.Alloc(kMaxCHIPDERCertLength), CHIP_ERROR_NO_MEMORY);
    MutableByteSpan nocSpan(noc.Get(), kMaxCHIPDERCertLength);

    Platform::ScopedMemoryBuffer<uint8_t> icac;
    ReturnErrorCodeIf(!icac.Alloc(kMaxCHIPDERCertLength), CHIP_ERROR_NO_MEMORY);
    MutableByteSpan icacSpan(icac.Get(), kMaxCHIPDERCertLength);

    Platform::ScopedMemoryBuffer<uint8_t> rcac;
    ReturnErrorCodeIf(!rcac.Alloc(kMaxCHIPDERCertLength), CHIP_ERROR_NO_MEMORY);
    MutableByteSpan rcacSpan(rcac.Get(), kMaxCHIPDERCertLength);

    ReturnErrorOnFailure(GenerateNOCChainAfterValidation(mNodeId, mFabricId, DAC, csr, nonce, rcacSpan, icacSpan, nocSpan));

    // TODO(#13825): Should always generate some IPK. Using a temporary fixed value until APIs are plumbed in to set it end-to-end
    // TODO: Force callers to set IPK if used before GenerateNOCChain will succeed.
    ByteSpan defaultIpkSpan = chip::GroupTesting::DefaultIpkValue::GetDefaultIpk();

    // The below static assert validates a key assumption in types used (needed for public API conformance)
    static_assert(CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES == kAES_CCM128_Key_Length, "IPK span sizing must match");

    // Prepare IPK to be sent back. A more fully-fledged operational credentials delegate
    // would obtain a suitable key per fabric.
    uint8_t ipkValue[CHIP_CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES];
    Crypto::AesCcm128KeySpan ipkSpan(ipkValue);

    ReturnErrorCodeIf(defaultIpkSpan.size() != sizeof(ipkValue), CHIP_ERROR_INTERNAL);
    memcpy(&ipkValue[0], defaultIpkSpan.data(), defaultIpkSpan.size());

    ChipLogProgress(Controller, "Providing certificate chain to the commissioner");
    onCompletion->mCall(onCompletion->mContext, CHIP_NO_ERROR, nocSpan, icacSpan, rcacSpan, MakeOptional(ipkSpan),
                        Optional<NodeId>());
    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::ObtainCsrNonce(MutableByteSpan & csrNonce)
{
    VerifyOrReturnError(csrNonce.size() == kCSRNonceLength, CHIP_ERROR_INVALID_ARGUMENT);
    char * certifier_nonce = util_generate_random_value(static_cast<int>(csrNonce.size()), ALLOWABLE_CHARACTERS);
    VerifyOrReturnError(certifier_nonce != nullptr, CHIP_ERROR_NO_MEMORY);
    memcpy(csrNonce.data(), certifier_nonce, csrNonce.size());
    XFREE(certifier_nonce);

    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::SetCertConfig(const char * certCfgPath, size_t len)
{
    mCertifierCfg = std::string(certCfgPath, len);
    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::SetKeystorePath(const std::string &keystorePath)
{
    mCertifierKeystore = keystorePath;
    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::SetKeystorePassphrase(const std::string &passphrase)
{
    mCertifierPassphrase = passphrase;
    return CHIP_NO_ERROR;
}

CHIP_ERROR CertifierOperationalCredentialsIssuer::ObtainOpCert(const ByteSpan & dac, const ByteSpan & csr, const ByteSpan & nonce,
                                                               MutableByteSpan & pkcs7OpCert, FabricId fabricId, NodeId nodeId)
{
    CHIP_ERROR err = CHIP_NO_ERROR;

    Platform::ScopedMemoryBuffer<char> base64CSR;
    base64CSR.Alloc(BASE64_ENCODED_LEN(static_cast<uint32_t>(csr.size())));
    std::string operationalID = "XFN-MTR";
    std::string crt;
    std::string pkcs7;
    std::string nodeIdStr = ToHexString<NodeId>(nodeId);
    std::string fabricIdStr = ToHexString<FabricId>(fabricId);
    std::unique_ptr<CERTIFIER, void (*)(CERTIFIER *)> cert_guard { certifier_api_easy_new(), certifier_api_easy_destroy };
    CERTIFIER *certifier = cert_guard.get();

    uint32_t base64CSRLen = Base64Encode32(csr.data(), static_cast<uint32_t>(csr.size()), base64CSR.Get());
    VerifyOrExit(base64CSRLen != UINT32_MAX, err = CHIP_ERROR_INTERNAL);

    // Always load configuration first, as Matter "owns" the set below.
    if (!mCertifierCfg.empty()) {
        certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_CFG_FILENAME, const_cast<char *>(mCertifierCfg.c_str()));
    }

    // This and passphrase are only relevant for CRT generation below.
    if (!mCertifierKeystore.empty()) { 
        certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_INPUT_P12_PATH, const_cast<char *>(mCertifierKeystore.c_str()));
        // certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_OUTPUT_P12_PATH, const_cast<char *>(mCertifierKeystore.c_str()));
    }

    if (!mCertifierPassphrase.empty()) {
        certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_INPUT_P12_PASSWORD, const_cast<char *>(mCertifierPassphrase.c_str()));
        // certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_OUTPUT_P12_PASSWORD, const_cast<char *>(mCertifierPassphrase.c_str()));
    }

    if (!mAuthCertificate.empty()) {
        certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_CA_INFO, const_cast<char *>(mAuthCertificate.c_str()));
    }

    if (!mAuthCertificatesDir.empty()) {
        certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_CA_PATH, const_cast<char *>(mAuthCertificatesDir.c_str()));
    }

    if (!mCertifierProfile.empty()) {
        certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_PROFILE_NAME, const_cast<char *>(mCertifierProfile.c_str()));
    }

    if (!mAuthorizationToken.empty()) {
        certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_AUTH_TYPE, const_cast<char *>("SAT"));
        certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_AUTH_TOKEN, const_cast<char *>(mAuthorizationToken.c_str()));
    }

    ChipLogProgress(Controller, "Generating Certificate Request Token");

    certifier_api_easy_set_mode(certifier, CERTIFIER_MODE_CREATE_CRT);
    VerifyOrExit(certifier_api_easy_perform(certifier) == 0, err = CHIP_ERROR_INTERNAL);
    crt = std::string(certifier_api_easy_get_result(certifier));

    ChipLogProgress(Controller, "Requesting certificate for Fabric ID %s, Node ID %s", fabricIdStr.c_str(), nodeIdStr.c_str());
    
    certifier_api_easy_set_mode(certifier, CERTIFIER_MODE_REGISTER);
    certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_CRT, const_cast<char *>(crt.c_str()));
    certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_CERTIFICATE_LITE, CERTIFIER_INT_TO_POINTER(true));
    certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_CN_PREFIX, const_cast<char *>(operationalID.c_str()));
    certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_NODE_ID, const_cast<char *>(nodeIdStr.c_str()));
    certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_PASSTHRU, CERTIFIER_INT_TO_POINTER(true));
    certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_CSR, const_cast<char *>(std::string(base64CSR.Get(), base64CSRLen).c_str()));
    certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_FABRIC_ID, const_cast<char *>(fabricIdStr.c_str()));
    certifier_api_easy_set_opt(certifier, CERTIFIER_OPT_VALIDITY_DAYS, CERTIFIER_INT_TO_POINTER(15 * 365));
    VerifyOrExit(certifier_api_easy_perform(certifier) == 0, err = CHIP_ERROR_INTERNAL);

    pkcs7 = std::string(certifier_api_easy_get_result(certifier));
    VerifyOrReturnError(pkcs7OpCert.size() >= pkcs7.length(), CHIP_ERROR_BUFFER_TOO_SMALL);
    memcpy(pkcs7OpCert.data(), pkcs7.data(), pkcs7.length());
    pkcs7OpCert.reduce_size(pkcs7.length());
exit:
    return err;
}

} // namespace Controller
} // namespace chip
