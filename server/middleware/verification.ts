import { NextFunction, Response } from 'express';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { ModifiedRequest } from '../app';
const JWT_SECRET = 'bequest';

/**
 * Helper function to extract JWT token from cookies
 * @param cookieString string|undefined
 * @returns token string|null
 */
function extractTokenFromCookie(cookieString: string|undefined): string|null {
  try {
    if (cookieString === undefined) {
      return null;
    }
    let tokenValue = '';
    const cookies = cookieString.split('; ');
    for (let i = 0; i < cookies.length; i += 1) {
      const cookie = cookies[i];
      const [name, value] = cookie.split('=');
      if (name === 'token') {
        tokenValue = value;
        break;
      }
    }
    return tokenValue;
  } catch (error) {
    console.error(`[extractTokenFromCookie]: ${error}`);
    return null;
  }
}

/**
 * Middleware to verify JWT token and attach user ID to the request object
 * @param req ModifiedRequest
 * @param res Response
 * @param next NextFunction
 * @returns void | Response
 */
export async function verifyToken(req: ModifiedRequest, res: Response, next: NextFunction){
  const { cookie } = req.headers;
  const token = extractTokenFromCookie(cookie)
  if (!token) {
    return res
      .status(401)
      .json({
        status: 'failure',
        error: 'User Not Authorized - No Token Provided'
      });
  }
  try {
    // Verify token with JWT_SECRET
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;

    // Attach the user ID to the request object
    if (decoded && typeof decoded === "object" && decoded.id) {
      req.id = decoded.id; // Attach user ID from token to the request
      req.token = token
      next(); // Proceed to the next middleware or route handler
    } else {
      throw new Error("Invalid Token Payload");
    }
  } catch (error) {
    // Handle token verification errors
    console.error(`[verifyToken]: ${error}`);
    return res.status(401).json({
      status: "failure",
      error: "User Not Authorized - Invalid or Expired Token",
    });
  }
}