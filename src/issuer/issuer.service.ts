import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { digest, generateSalt, ES256 } from '@sd-jwt/crypto-nodejs';
import * as crypto from 'crypto';


export enum RequestedCredentialType {
  SD_JWT = 'sd-jwt',
  SD_JWT_VC = 'sd-jwt-vc',
}

interface CredentialRequestParams {
  firstname: string;
  lastname: string;
  email: string;
  fi_vc_recipient?: string;
  fi_vc_reason?: string;
  fi_vc_sha256?: string;
  walletPublicKey: string;
  challenge: string;
}





@Injectable()
export class IssuerService implements OnModuleInit {
  private readonly logger = new Logger(IssuerService.name);
  private sdjwt: SDJwtVcInstance;
  private privateKey: JsonWebKey;
  private publicKey: JsonWebKey;

  // challenge -> expiry timestamp (ms)
  private readonly challenges = new Map<string, number>();

  async onModuleInit() {
    // 1. Génération des clés
    const { privateKey, publicKey } = await ES256.generateKeyPair();
    this.privateKey = privateKey;
    this.publicKey = publicKey;

    const signer = await ES256.getSigner(privateKey);
    const verifier = await ES256.getVerifier(publicKey);

    this.sdjwt = new SDJwtVcInstance({
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: ES256.alg, // "ES256"
      signer,
      verifier,
    });
  }

  private async loadOrGenerateKeyPair() {

  }



  generateChallenge(): string {
    // Purge expired challenges
    const now = Date.now();
    for (const [ch, expiry] of this.challenges) {
      if (expiry < now) this.challenges.delete(ch);
    }
    const challenge = crypto.randomBytes(32).toString('base64');
    this.challenges.set(challenge, now + 5 * 60 * 1000); // 5-minute TTL
    return challenge;
  }

  async issueCredential(
    params: CredentialRequestParams,
    requestedCredential = RequestedCredentialType.SD_JWT_VC,
  ): Promise<string> {
    const expiry = this.challenges.get(params.challenge);
    if (!expiry || expiry < Date.now()) {
      throw new Error('Invalid or expired challenge');
    }
    this.challenges.delete(params.challenge); // one-time use

    const now = Math.floor(Date.now() / 1000);
    const iat = now + 365 * 24 * 60 * 60;
    const issuer = process.env.ISSUER_URL ?? 'http://localhost:3000';

    if (requestedCredential == RequestedCredentialType.SD_JWT_VC) {
      const payload = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: '123',
        type: ['VerifiableCredential'],
        issuer: 'did:web:localhost:3000',
        validFrom: new Date(now).toISOString(),
        validUntil: new Date(iat).toISOString(),
        vct: `${issuer}/credentials/identity`,
        credentialSubject: {
          id: 'did:example:ebfeb1f712ebc6f1c276e12ec21',
          firstname: params.firstname,
          lastname: params.lastname,
          email: params.email,
          fi_vc_recipient: params.fi_vc_recipient ?? '',
          fi_vc_reason: params.fi_vc_reason ?? '',
          fi_vc_sha256: params.fi_vc_sha256 ?? '',
          age_over_18: true,
          age_over_21: true,
        },
      };

      return this.sdjwt.issue(payload, {
        _sd: ['id', 'issuer'],
        credentialSubject: {
          _sd: [
            'id',
            'firstname',
            'lastname',
            'email',
            'fi_vc_recipient',
            'fi_vc_reason',
            'fi_vc_sha256',
            'age_over_18',
            'age_over_21',
          ],
        },
      });
    } else {
      const payload = {
        iss: issuer,
        sub: params.walletPublicKey,
        iat: now,
        exp: now + 365 * 24 * 60 * 60,
        vct: `${issuer}/credentials/identity`,
        firstname: params.firstname,
        lastname: params.lastname,
        email: params.email,
        fi_vc_recipient: params.fi_vc_recipient ?? '',
        fi_vc_reason: params.fi_vc_reason ?? '',
        fi_vc_sha256: params.fi_vc_sha256 ?? '',
        age_over_18: true,
      };

      console.log("Issuing SD-JWT credential:", payload)
      return this.sdjwt.issue(payload, {
        _sd: [
          'iat',
          'age_over_18',
          'firstname',
          'lastname',
          'email',
          'fi_vc_recipient',
          'fi_vc_reason',
          'fi_vc_sha256',
        ],
      });
    }
  }


  async verifyCredential(
    credential: string,
  ): Promise<{ valid: boolean; payload?: Record<string, unknown>; error?: string }> {
    try {
      const result = await this.sdjwt.verify(credential);
      return { valid: true, payload: result.payload as Record<string, unknown> };
    } catch (err) {
      return {
        valid: false,
        error: err instanceof Error ? err.message : 'Verification failed',
      };
    }
  }

  getPublicKeyJwk() {
    return this.publicKey;
  }
}
