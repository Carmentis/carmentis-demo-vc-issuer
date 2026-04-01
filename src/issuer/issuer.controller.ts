import {
  Body,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Post,
} from '@nestjs/common';
import { IssuerService, RequestedCredentialType } from './issuer.service';

class IssueCredentialDto {
  firstname: string;
  lastname: string;
  email: string;
  fi_vc_recipient?: string;
  fi_vc_reason?: string;
  fi_vc_sha256?: string;
  walletPublicKey: string;
  challenge: string;
  format?: 'sd-jwt' | 'sd-jwt-vc';
}

class VerifyCredentialDto {
  credential: string;
}

@Controller('api')
export class IssuerController {
  constructor(private readonly issuerService: IssuerService) {}

  @Get('challenge')
  getChallenge() {
    return { challenge: this.issuerService.generateChallenge() };
  }

  @Get('jwks')
  getPublicKey() {
    return { keys: [this.issuerService.getPublicKeyJwk()] };
  }

  @Post('credential')
  async issueCredential(@Body() body: IssueCredentialDto) {
    if (!body.firstname || !body.lastname || !body.email) {
      throw new HttpException(
        'firstname, lastname and email are required',
        HttpStatus.BAD_REQUEST,
      );
    }
    if (!body.walletPublicKey || !body.challenge) {
      throw new HttpException(
        'walletPublicKey and challenge are required',
        HttpStatus.BAD_REQUEST,
      );
    }

    const credentialType =
      body.format === 'sd-jwt'
        ? RequestedCredentialType.SD_JWT
        : RequestedCredentialType.SD_JWT_VC;

    try {
      const credential = await this.issuerService.issueCredential(
        body,
        credentialType,
      );
      return { credential, format: body.format ?? 'sd-jwt-vc' };
    } catch (err) {
      throw new HttpException(
        err instanceof Error ? err.message : 'Failed to issue credential',
        HttpStatus.BAD_REQUEST,
      );
    }
  }

  @Post('verify')
  async verifyCredential(@Body() body: VerifyCredentialDto) {
    if (!body.credential) {
      throw new HttpException('credential is required', HttpStatus.BAD_REQUEST);
    }
    return this.issuerService.verifyCredential(body.credential);
  }
}
