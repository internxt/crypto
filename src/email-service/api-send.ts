import emailjs from '@emailjs/browser';
import { EmailPublicParameters, HybridEncryptedEmail, PwdProtectedEmail } from '../types';
import { hybridEncyptedEmailToBase64, pwdProtectedEmailToBase64 } from '../email-crypto/converters';

/**
 * Email sender class
 *
 */
export class EmailServiceAPI {
  private readonly serviceId: string;
  private readonly templateId: string;
  private readonly publicKey: string;

  constructor(serviceId: string, templateId: string, publicKey: string) {
    this.serviceId = serviceId;
    this.templateId = templateId;
    this.publicKey = publicKey;
  }

  /**
   * Sends an email to the server
   *
   * @param content - The email content (encrypted)
   * @param param - The email public parameters
   * @returns The server response
   */
  async sendEmail(content: string, param: EmailPublicParameters) {
    try {
      const templateParams = {
        from_email: param.sender.email,
        from_name: param.sender.name,
        to_email: param.recipient.email,
        to_name: param.recipient.name,
        email_subject: param.subject,
        email_body: content,
        timestamp: new Date().toISOString(),
      };

      await emailjs.send(this.serviceId, this.templateId, templateParams, this.publicKey);
    } catch (error) {
      throw new Error(`Failed to send an email ${(error as Error).message}`, { cause: error });
    }
  }

  /**
   * Sends a hybridly encrypted email to a particular recipient recipient
   *
   * @param encryptedEmail - The hybridly encrypted email
   * @returns The server reply
   */
  async sendHybridEmail(encryptedEmail: HybridEncryptedEmail) {
    try {
      if (encryptedEmail.recipientEmail !== encryptedEmail.params.recipient.email) {
        throw new Error('Email is encrypted for another recipient');
      }
      const body = hybridEncyptedEmailToBase64(encryptedEmail);
      await this.sendEmail(body, encryptedEmail.params);
    } catch (error) {
      throw new Error(`Failed to email to the recipient: ${(error as Error).message}`, { cause: error });
    }
  }

  /**
   * Sends a password-protected email to a particular recipient
   *
   * @param protectedEmail - The password protected email
   * @param recipient - The email recipient
   * @returns The server reply
   */
  async sendPwdProtectedEmail(protectedEmail: PwdProtectedEmail) {
    try {
      const body = pwdProtectedEmailToBase64(protectedEmail);
      await this.sendEmail(body, protectedEmail.params);
    } catch (error) {
      throw new Error(`Failed to email to the recipient ${(error as Error).message}`, { cause: error });
    }
  }
}

export function getEmailServiceAPI(serviceId: string, templateId: string, publicKey: string): EmailServiceAPI {
  return new EmailServiceAPI(serviceId, templateId, publicKey);
}
