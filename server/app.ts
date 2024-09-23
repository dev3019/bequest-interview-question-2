import express, { Request, Response } from 'express';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import CryptoJS from 'crypto-js';
import jwt from 'jsonwebtoken';
import { redisInstance } from './CacheManager';
import { CacheError } from './CacheManager';
import { verifyToken } from './middleware/verification';

const PORT = 8080;
const app = express();
const JWT_SECRET = 'bequest';
const serverSecret = CryptoJS.lib.WordArray.random(32).toString(
  CryptoJS.enc.Hex
); // 256-bit key, can be used as an env so if system goes down can still be persisted
app.use(
  cors({
    origin: 'http://localhost:3000', // specify the origin
    credentials: true, // allow credentials (cookies, authorization headers)
  })
);
app.use(express.json());
export interface ModifiedRequest extends Request {
  id?: string;
  token?: string;
}
const getKey = (secret: string) => {
  return CryptoJS.SHA256(secret).toString(CryptoJS.enc.Hex).slice(0, 64);
};
// Helper function to generate HMAC
const generateHMAC = (data: string, secret: string) => {
  return CryptoJS.HmacSHA256(data, secret).toString();
};

export const generateServerHMAC = (data: string) => {
  return CryptoJS.HmacSHA256(data, serverSecret).toString();
};

export const encryptData = (data: string, id: string, secret: string) => {
  // Encrypt the data
  const key = getKey(secret);
  const iv = id.slice(0, 16);
  const encryptedData = CryptoJS.AES.encrypt(
    data,
    CryptoJS.enc.Hex.parse(key),
    {
      iv: CryptoJS.enc.Hex.parse(iv),
    }
  ).toString();
  return encryptedData;
};

const decryptData = (encryptedData: string, id: string, secret: string) => {
  const key = getKey(secret);
  const iv = id.slice(0, 16);
  const bytes = CryptoJS.AES.decrypt(
    encryptedData,
    CryptoJS.enc.Hex.parse(key),
    {
      iv: CryptoJS.enc.Hex.parse(iv),
    }
  );
  const decryptedData = bytes.toString(CryptoJS.enc.Utf8);
  return decryptedData;
};

// Routes
app.get('/connect', async (req: Request, res: Response) => {
  try {
    const id = uuidv4();
    const secret = CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Hex); // 256-bit key

    // Store the secret in Redis
    await redisInstance.putUserInfo({
      id,
      secret,
    });

    // Generate JWT token
    const token = jwt.sign({ id }, JWT_SECRET, { expiresIn: '1h' });

    return res
      .cookie('token', token, {
        maxAge: 3600 * 1000, // 1 hour
        httpOnly: true,
      })
      .status(201)
      .json({
        status: 'success',
        message: 'New secret and token created',
        data: {
          id,
          secret,
        },
      });
  } catch (error) {
    if (error instanceof CacheError) {
      console.error(`[CacheManager]: ${error}`);
      return res.status(503).json({
        status: 'failure',
        error: 'Service Unavailable',
      });
    } else {
      console.error(`[connect]: ${error}`);
      return res.status(500).json({
        status: 'failure',
        error,
      });
    }
  }
});

app.get('/', verifyToken, async (req: ModifiedRequest, res: Response) => {
  try {
    const { id } = req;
    if (!id) {
      return res
        .status(400)
        .json({ status: 'failure', message: 'Bad Request.' });
    }

    //@note retrieve secret from cache
    const userInfo = await redisInstance.getUserInfo(id);
    if (!userInfo) {
      //@note if secret not present then user should connect again
      return res.status(400).json({
        status: 'failure',
        message: 'Secret missing, please connect again.',
      });
    }
    const { secret } = userInfo;

    //@note retrieve data from cache
    const userData = await redisInstance.getUserData(id);
    if (!userData) {
      //@note if data not present then user should save it again
      return res.status(400).json({
        status: 'failure',
        message: 'Data missing, please save data again.',
      });
    }
    const { data, hmac: storedHmac } = userData;
    let encryptedData = encryptData(data, id, secret);
    const calculatedServerHmac = generateServerHMAC(encryptedData);

    if (calculatedServerHmac !== storedHmac) {
      console.error(`Data Tampering Detected for user ${id}, saving backedup data if present.`);
      const backupData = await redisInstance.getBackupUserData(id);
      if (!backupData) {
        return res.status(400).json({
          status: 'failure',
          message:
            'Data tampered and backup missing, please connect and save data again.',
        });
      }
      encryptedData = encryptData(backupData, id, secret);
    }

    //@note Generate HMAC to ensure data integrity
    const hmac = generateHMAC(encryptedData, secret);
    return res.status(200).json({
      status: 'success',
      data: {
        encryptedData,
        hmac,
      },
    });
  } catch (error) {
    if (error instanceof CacheError) {
      console.error(`[CacheManager]: ${error}`);
      return res.status(503).json({
        status: 'failure',
        error: 'Service Unavailable',
      });
    } else {
      console.error(`[/]: ${error}`);
      return res.status(500).json({
        status: 'failure',
        error,
      });
    }
  }
});

app.post('/', verifyToken, async (req: ModifiedRequest, res: Response) => {
  try {
    const { data: encryptedData, hmac } = req.body;
    const { id } = req;
    if (!id) {
      return res
        .status(400)
        .json({ status: 'failure', message: 'Bad Request.' });
    }

    //@note retrieve secret from cache
    const userInfo = await redisInstance.getUserInfo(id);
    if (!userInfo) {
      //@note if secret not present then user should connect again
      return res.status(400).json({
        status: 'failure',
        message: 'Secret missing, please connect again.',
      });
    }
    const { secret } = userInfo;
    // Decrypt data
    const decryptedData = decryptData(encryptedData, id, secret);

    // Verify HMAC for data integrity
    const calculatedHmac = generateHMAC(encryptedData, secret);
    if (calculatedHmac !== hmac) {
      return res
        .status(400)
        .json({ status: 'failure', message: 'Data integrity compromised.' });
    }

    const serverHmac = generateServerHMAC(encryptedData);

    await redisInstance.putUserData({
      id,
      data: decryptedData,
      hmac: serverHmac,
    });

    return res.status(200).json({ status: 'success', message: 'Data Saved' });
  } catch (error) {
    if (error instanceof CacheError) {
      console.error(`[CacheManager]: ${error}`);
      return res.status(503).json({
        status: 'failure',
        error: 'Service Unavailable',
      });
    } else {
      console.error(`[/]: ${error}`);
      return res.status(500).json({
        status: 'failure',
        error,
      });
    }
  }
});

app.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
});
