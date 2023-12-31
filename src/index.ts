import 'dotenv/config';
import crypto from 'node:crypto';

enum EventEnum {
  ZUP_END_STEP = 'zup.end_step',
}

export type BodyType = {
  event: EventEnum;
  data: string;
};

export type ZupEndStepType = {
  event: string;
  data: {
    stepId: string;
    stepName: string;
    stepType: string;
  };
};

export class Dynzup {
  private secretKey: string;

  constructor(secretKey: string) {
    this.secretKey = secretKey;
  }

  private async hashString(value: string, rounds = 8): Promise<string> {
    let hashedValue = value;

    for (let i = 0; i < rounds; i++) {
      hashedValue = crypto
        .createHash('sha256')
        .update(hashedValue)
        .digest('hex');
    }
    return hashedValue;
  }

  private async compareSignature(
    compareSignature: string,
    signature: string
  ): Promise<boolean> {
    const hashedSignature = await this.hashString(compareSignature);

    return hashedSignature === signature;
  }
  async constructEvent(
    payload: BodyType,
    signature: string
  ): Promise<BodyType> {
    const dynzupKey = process.env.DYNZUP_KEY || 'dynzup-';
    const isValidSignature = await this.compareSignature(
      `${dynzupKey}${this.secretKey}`,
      signature
    );

    if (!isValidSignature) {
      throw new Error('Invalid signature');
    }

    if (!Object.values(EventEnum).includes(payload.event)) {
      throw new Error('Invalid event type');
    }

    const initVector = crypto
      .createHash('sha512')
      .update(this.secretKey)
      .digest('hex')
      .substring(0, 16);

    const decipher = crypto.createDecipheriv(
      'aes-256-cbc',
      this.secretKey,
      initVector
    );

    let decryptedData = decipher.update(payload.data, 'hex', 'utf-8');

    decryptedData += decipher.final('utf8');

    const requestBody = {
      event: payload.event,
      data: JSON.parse(decryptedData),
    };

    return requestBody;
  }
}
