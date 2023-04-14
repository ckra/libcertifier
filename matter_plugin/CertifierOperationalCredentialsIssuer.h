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
#pragma once

#include <controller/OperationalCredentialsDelegate.h>
#include <credentials/CHIPCert.h>
#include <crypto/CHIPCryptoPAL.h>
#include <lib/core/PeerId.h>
#include <lib/support/DLLUtil.h>
#include <string>
#include <iostream>
#include <iomanip>

struct CERTIFIER;

namespace chip {
namespace Controller {

class DLL_EXPORT CertifierOperationalCredentialsIssuer : public OperationalCredentialsDelegate
{
public:
    virtual ~CertifierOperationalCredentialsIssuer() {}

    CHIP_ERROR GenerateNOCChain(const ByteSpan & csrElements, const ByteSpan & csrNonce, const ByteSpan & attestationSignature,
                                const ByteSpan & attestationChallenge, const ByteSpan & DAC, const ByteSpan & PAI,
                                Callback::Callback<OnNOCChainGeneration> * onCompletion) override;

    void SetNodeIdForNextNOCRequest(NodeId nodeId) override { mNodeId = nodeId; }
    void SetFabricIdForNextNOCRequest(FabricId fabricId) override { mFabricId = fabricId; }

    CHIP_ERROR ObtainCsrNonce(MutableByteSpan & csrNonce) override;

    CHIP_ERROR GenerateNOCChainAfterValidation(NodeId nodeId, FabricId fabricId, const ByteSpan & dac, const ByteSpan & csr,
                                               const ByteSpan & nonce, MutableByteSpan & rcac, MutableByteSpan & icac,
                                               MutableByteSpan & noc);

    /**
     * @brief Set the xpki.io trust anchor (single root)
     * 
     * @param authCertPath 
     * @param len 
     * @note this will override any JSON configuration, if set.
     * @return CHIP_ERROR This operation is always successful.
     */

    void SetAuthCertificate(const std::string &authCertPath)
    {
        mAuthCertificate = authCertPath;
    }

    /**
     * @brief Set the xpki.io trust anchors (directory of roots)
     *
     * @param authCertPath A path to a directory containing trust anchors to accept
     * @note This will override any JSON configuration, if set.
     * @return CHIP_ERROR This operation is always successful.
     */
    void SetAuthCertPath(const std::string &authCertPath)
    {
        mAuthCertificatesDir = authCertPath;
    }

    /**
     * @brief Set the xPKI CA name
     * @ref https://etwiki.sys.comcast.net/display/SATS/Profiles
     * 
     * @param caName 
     */
    void SetCAProfile(const std::string &caName)
    {
        mCertifierProfile = caName;
    }

    /**
     * @brief Set the libcertifier JSON configuration path. This should normally
     * be unset.
     * 
     * @param certCfgPath 
     * @param len 
     * @return CHIP_ERROR 
     */
    CHIP_ERROR SetCertConfig(const char * certCfgPath, size_t len);

    /**
     * @brief Set the path to the libcertifier system keystore. Default is <pwd>/libcertifier.p12
     * @note if set, this overrides any previously loaded JSON configuration
     * @param keystorePath 
     * @return CHIP_ERROR 
     */
    CHIP_ERROR SetKeystorePath(const std::string &keystorePath);

    /**
     * @brief Set the passphrase to unlock the libcertifier system keystore.
     * @note if set, this overrides any previously loaded JSON configuration
     * @param passphrase 
     * @return CHIP_ERROR 
     */
    CHIP_ERROR SetKeystorePassphrase(const std::string &passphrase);

    /**
     * @brief Set the xPKI authorization token for NOC chain validation
     * 
     * @param token A valid bearer token (e.g., SAT)
     */
    void SetAuthToken(const std::string &token)
    {
        mAuthorizationToken = token;
    }

    /**
     * @brief Set the fabric IPK for the next NOC chain generation
     * 
     * @param active_ipk_span The current IPK for the fabric that is commissioning
     * @note Be sure to invoke this to synchronize the commissioning fabric's active IPK
     *       when starting a commissioning session. If the IPK doesn't match the commissioner's
     *       active IPK, CASE will fail to establish.
     * @return CHIP_ERROR CHIP_ERROR_INVALID_ARGUMENT if input IPK span is empty
     */
    inline CHIP_ERROR SetIPKForNextNOCRequest(const chip::Crypto::AesCcm128KeySpan &active_ipk_span)
    {
        mIPK = MakeOptional(chip::Crypto::AesCcm128Key(active_ipk_span));

        return CHIP_NO_ERROR;
    }

private:
    NodeId mNodeId;
    FabricId mFabricId;

    /**
     * @brief Single trust anchor for xPKI (certifier.xpki.io) https
     * peer validation
     */
    std::string mAuthCertificate;

    /**
     * @brief Directory containing trust anchors for xPKI (certifier.xpki.io) https
     * peer validation
     * 
     */
    std::string mAuthCertificatesDir;

    /**
     * @brief Path to JSON libcertifier configuration file
     * 
     */
    std::string mCertifierCfg;

    /**
     * @brief Path to PKCS#12 libcertifier keystore. This will store the commissioner's
     * Node Operational Certificate
     */
    std::string mCertifierKeystore = "seed.p12";

    /**
     * @brief Passphrase to open libcertifier keystore
     * 
     */
    std::string mCertifierPassphrase = "changeit";

    /**
     * @brief The Matter CA to request certificates from
     */
    std::string mCertifierProfile = "XFN_Matter_OP_Class_3_ICA";

    std::string mAuthorizationToken;

    chip::Optional<chip::Crypto::AesCcm128Key> mIPK;

    /**
     * @brief Makes a string that represents a number in hex, with leading zeroes.
     * 
     * @tparam T A numeric type (int, uint64_t, ...)
     * @param number
     * @return std::string 
     * //TODO: Use c++20 'concept' to constrain T to numeric.
     */
    template<typename T>
    inline std::string ToHexString(T number)
    {
        std::stringstream os;
        
        // Matter requires uppercase hex for ID attributes; xPKI wants no radix indicator (0x).
        os << std::uppercase << std::hex << std::setfill('0') << std::setw(sizeof(T)*2) << std::right << number;

        return os.str();
    }

    CHIP_ERROR ObtainOpCert(const ByteSpan & dac, const ByteSpan & csr, const ByteSpan & nonce, MutableByteSpan & pkcs7OpCert,
                            FabricId fabricId, NodeId nodeId);
};

} // namespace Controller
} // namespace chip
