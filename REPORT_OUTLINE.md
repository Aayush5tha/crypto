# Report Outline (ST6051CEM)

## 1. Introduction
- Project overview and goals
- Scope and limitations

## 2. Cryptographic Techniques Used
- RSA vs ECC key generation
- Digital signatures (RSA-PSS / ECDSA)
- Hybrid encryption (RSA-OAEP + AES-GCM, ECDH + AES-GCM)
- PKI components (certificates, CSRs, CA signing)

## 3. System Design and Architecture
- GUI workflow design
- Module breakdown (GUI, crypto core, storage, attacks)
- Data formats (JSON for signatures/encryption, PKCS#12 for keystore)

## 4. Security Features and Threat Mitigation
- Integrity checks and signatures
- Replay prevention (nonce cache)
- MITM detection (certificate fingerprints)
- Secure key storage (PKCS#12)
- Revocation (CRL)

## 5. Implementation Details
- Key generation and certificate issuance flow
- Signing and verification flow
- Encryption and decryption flow
- Keystore creation and loading

## 6. Use Cases
- Secure document signing
- Encrypted file transfer
- Device trust bootstrap with local CA and revocation

## 7. Testing and Validation
- Unit tests summary
- Attack simulation results
- Multi-user signing/verification scenario

## 8. Challenges and Improvements
- GUI UX challenges
- Potential improvements (OCSP, cert chain validation, key pinning)

## 9. Conclusion
- Outcomes and learning

## Appendix
- GitHub repo link
- Video demo link
