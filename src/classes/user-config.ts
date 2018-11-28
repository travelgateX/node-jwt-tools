export class UserConfig {

    validationAuthUrl: string;
    validationPublicKey: string;
    claimUrl: string;
    claimIam: string;
    claimMemberId: string;

    constructor(pAuthUrl: string, pCertificate: string, pClaimUrl: string, pClaimIam: string, pClaimMemberId: string) {
        this.validationAuthUrl = pAuthUrl;
        this.validationPublicKey = pCertificate;
        this.claimUrl = pClaimUrl;
        this.claimIam = pClaimIam;
        this.claimMemberId = pClaimMemberId;
    }
}