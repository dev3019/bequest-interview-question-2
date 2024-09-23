import { RedisClientType, createClient } from 'redis';
import { encryptData, generateServerHMAC } from './app';

interface UserInfo {
  id: string;
  secret: string;
}

interface UserData {
  id: string;
  data: string;
  hmac: string;
}

export class CacheError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CacheError';
  }
}
class CacheManager {
  private static instance: CacheManager;
  private redisClient: RedisClientType;

  private constructor() {
    this.redisClient = createClient();
    this.redisClient.on('error', (err) =>
      console.error('Redis Client Error', err)
    );
    this.redisClient.connect().catch(console.error);
  }

  /**
   *
   * @returns instance of CacheManager
   */
  public static getInstance() {
    if (!CacheManager.instance) {
      CacheManager.instance = new CacheManager();
    }
    return CacheManager.instance;
  }

  private async ensureConnected() {
    if (!this.redisClient.isOpen) {
      await this.redisClient.connect();
    }
  }

  /**
   * Takes in User's info and saves it to cache for 1 hr
   * @param userInfo UserInfo
   */
  public async putUserInfo(userInfo: UserInfo) {
    try {
      await this.ensureConnected();
      await this.redisClient.set(`userInfo:${userInfo.id}`, userInfo.secret, {
        EX: 60 * 60,
      }); // Expire the key after 1 hour
    } catch (error) {
      throw new CacheError(
        error instanceof Error ? error.message : 'Unknown cache error'
      );
    }
  }

  /**
   * Takes in User's data and saves it to cache for 15 mins
   * @param userData UserData
   */
  public async putUserData(userData: UserData) {
    try {
      await this.ensureConnected();

      // Start a Redis transaction to handle both operations atomically
      const multi = this.redisClient.multi();

      // Set normal data
      multi.set(
        `userData:${userData.id}`,
        JSON.stringify({
          data: userData.data,
          hmac: userData.hmac,
        }),
        {
          EX: 60 * 15, // 15 minutes expiry
        }
      );

      // Set backup data within the same transaction
      multi.set(`backup-userData:${userData.id}`, userData.data, {
        EX: 60 * 15, // 15 minutes expiry
      });

      // Execute the transaction
      await multi.exec();
    } catch (error) {
      throw new CacheError(
        error instanceof Error ? error.message : 'Unknown cache error'
      );
    }
  }

  /**
   * saves user's backup data to cache for 15 mins
   * @param userData UserData
   */
  public async putBackupUserData(userData: UserData) {
    try {
      await this.ensureConnected();
      await this.redisClient.set(
        `backup-userData:${userData.id}`,
        userData.data,
        {
          EX: 60 * 15,
        }
      ); // Expire the key after 15 mins
    } catch (error) {
      throw new CacheError(
        error instanceof Error ? error.message : 'Unknown cache error'
      );
    }
  }

  /**
   * if user info is present refreshes the expiry of info in cache and then returns else returns null
   * @param id string
   * @returns Promise<UserInfo|null>
   */
  public async getUserInfo(id: string): Promise<UserInfo | null> {
    try {
      await this.ensureConnected();
      const secret = await this.redisClient.get(`userInfo:${id}`);
      if (secret) {
        const userInfo = {
          id,
          secret,
        };
        await this.putUserInfo(userInfo);
        return userInfo;
      }
      return null;
    } catch (error) {
      throw new CacheError(
        error instanceof Error ? error.message : 'Unknown cache error'
      );
    }
  }

  /**
   * if user data is present then returns data else returns null
   * @param id string
   * @returns Promise<UserData|null>
   */
  public async getUserData(id: string): Promise<UserData | null> {
    try {
      await this.ensureConnected();
      const data = await this.redisClient.get(`userData:${id}`);
      if (data) {
        const parsedData = JSON.parse(data);
        const userData = {
          id,
          data: parsedData.data,
          hmac: parsedData.hmac,
        };
        return userData;
      }
      return null;
    } catch (error) {
      throw new CacheError(
        error instanceof Error ? error.message : 'Unknown cache error'
      );
    }
  }

  /**
   * Returns backed up UserData if normal UserData is tampered, and then saves it to normal UserData
   * @param id string
   * @returns Promise<string|null>
   */
  public async getBackupUserData(id: string) {
    try {
      await this.ensureConnected();
      const data = await this.redisClient.get(`backup-userData:${id}`);
      if (data) {
        const secret = await this.redisClient.get(`userInfo:${id}`);
        if (secret) {
          const encryptedData = encryptData(data, id, secret);
          const serverHmac = generateServerHMAC(encryptedData);
          const userData = {
            id,
            data,
            hmac: serverHmac,
          };
          await this.putUserData(userData);
          return userData.data;
        }
      }
      return null;
    } catch (error) {
      throw new CacheError(
        error instanceof Error ? error.message : 'Unknown cache error'
      );
    }
  }
}

export const redisInstance = CacheManager.getInstance();
