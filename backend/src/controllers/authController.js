import User from '../models/User.js';
import { sendTokenResponse, verifyRefreshToken, generateAccessToken } from '../utils/jwt.js';
import AppError from '../utils/AppError.js';
import { ErrorCodes } from '../utils/errorCodes.js';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const WIKIMEDIA_AUTH_URL = 'https://meta.wikimedia.org/w/rest.php/oauth2/authorize';
const WIKIMEDIA_TOKEN_URL = 'https://meta.wikimedia.org/w/rest.php/oauth2/access_token';
const WIKIMEDIA_PROFILE_URL = 'https://meta.wikimedia.org/w/rest.php/oauth2/resource/profile';

const frontendUrl = () => process.env.FRONTEND_URL || 'http://localhost:3000';

const requireWikimediaConfig = () => {
  const required = ['WIKIMEDIA_CLIENT_ID', 'WIKIMEDIA_CLIENT_SECRET', 'WIKIMEDIA_REDIRECT_URI'];
  if (required.some((name) => !process.env[name])) {
    throw new AppError('Wikimedia login is not configured', 503, ErrorCodes.INTERNAL_SERVER_ERROR);
  }
};

const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: 10 * 60 * 1000
};

// @desc    Start Wikimedia OAuth 2.0 authorization-code flow
// @route   GET /api/auth/wikimedia
// @access  Public
export const startWikimediaLogin = (req, res, next) => {
  try {
    requireWikimediaConfig();
    const state = crypto.randomBytes(32).toString('hex');
    const params = new URLSearchParams({
      client_id: process.env.WIKIMEDIA_CLIENT_ID,
      response_type: 'code',
      redirect_uri: process.env.WIKIMEDIA_REDIRECT_URI,
      state
    });

    res.cookie('wikimedia_oauth_state', state, cookieOptions);
    res.redirect(`${WIKIMEDIA_AUTH_URL}?${params.toString()}`);
  } catch (error) {
    next(error);
  }
};

// @desc    Complete Wikimedia OAuth login and create SourceWiki JWTs
// @route   GET /api/auth/wikimedia/callback
// @access  Public
export const wikimediaCallback = async (req, res, next) => {
  try {
    requireWikimediaConfig();
    const { code, state, error: oauthError } = req.query;
    const expectedState = req.cookies.wikimedia_oauth_state;
    res.clearCookie('wikimedia_oauth_state', cookieOptions);

    if (oauthError) return res.redirect(`${frontendUrl()}/auth?error=wikimedia_cancelled`);
    if (!code || !state || !expectedState || state !== expectedState) {
      return next(new AppError('Invalid Wikimedia OAuth state', 400, ErrorCodes.AUTHENTICATION_FAILED));
    }

    const tokenResponse = await fetch(WIKIMEDIA_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        client_id: process.env.WIKIMEDIA_CLIENT_ID,
        client_secret: process.env.WIKIMEDIA_CLIENT_SECRET,
        redirect_uri: process.env.WIKIMEDIA_REDIRECT_URI
      })
    });
    const tokenData = await tokenResponse.json();
    if (!tokenResponse.ok || !tokenData.access_token) {
      throw new AppError('Wikimedia authorization failed', 401, ErrorCodes.AUTHENTICATION_FAILED);
    }

    const profileResponse = await fetch(WIKIMEDIA_PROFILE_URL, {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const profile = await profileResponse.json();
    if (!profileResponse.ok || !profile.sub || !profile.username) {
      throw new AppError('Unable to read Wikimedia profile', 401, ErrorCodes.AUTHENTICATION_FAILED);
    }

    let user = await User.findOne({ where: { wikimediaId: String(profile.sub) } });
    if (!user) {
      const safeName = profile.username.replace(/[^A-Za-z0-9_]/g, '').slice(0, 22) || 'WikimediaUser';
      let username = `wiki_${safeName}`.slice(0, 30);
      let suffix = 1;
      while (await User.findOne({ where: { username } })) {
        username = `wiki_${safeName.slice(0, 26)}${suffix++}`.slice(0, 30);
      }
      user = await User.create({
        username,
        email: `wikimedia-${profile.sub}@users.invalid`,
        password: crypto.randomBytes(48).toString('base64url'),
        country: 'Unknown',
        wikimediaId: String(profile.sub),
        wikimediaUsername: profile.username
      });
    } else if (user.wikimediaUsername !== profile.username) {
      await user.update({ wikimediaUsername: profile.username });
    }

    if (!user.isActive) {
      return next(new AppError('Account is deactivated', 401, ErrorCodes.ACCOUNT_INACTIVE));
    }

    // A short-lived, one-time browser handoff avoids putting app JWTs in a URL.
    const handoff = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '60s' });
    res.cookie('wikimedia_oauth_handoff', handoff, cookieOptions);
    res.redirect(`${frontendUrl()}/auth/callback`);
  } catch (error) {
    next(error);
  }
};

// @desc    Exchange the short-lived OAuth browser handoff for SourceWiki JWTs
// @route   POST /api/auth/wikimedia/session
// @access  Public
export const exchangeWikimediaSession = async (req, res, next) => {
  try {
    const handoff = req.cookies.wikimedia_oauth_handoff;
    res.clearCookie('wikimedia_oauth_handoff', cookieOptions);
    if (!handoff) return next(new AppError('Wikimedia session is missing', 401, ErrorCodes.AUTH_TOKEN_MISSING));
    const decoded = jwt.verify(handoff, process.env.JWT_SECRET);
    const user = await User.findByPk(decoded.id);
    if (!user || !user.isActive) return next(new AppError('User not found or inactive', 401, ErrorCodes.AUTHENTICATION_FAILED));
    sendTokenResponse(user, 200, res);
  } catch (error) {
    next(new AppError('Wikimedia session has expired', 401, ErrorCodes.AUTH_TOKEN_INVALID));
  }
};

// @desc    Register user
// @route   POST /api/auth/register
// @access  Public
export const register = async (req, res, next) => {
  try {
    const { username, email, password, country } = req.body;

    // Create user
    const user = await User.create({
      username,
      email,
      password,
      country
    });

    sendTokenResponse(user, 201, res);
  } catch (error) {
    next(error);
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
export const login = async (req, res, next) => {
  try {
    const { username, password } = req.body;

    // Find user and include password
    const user = await User.scope('withPassword').findOne({ where: { username: username ?? null } });

    if (!user) {
      return next(new AppError('Invalid credentials', 401, ErrorCodes.INVALID_CREDENTIALS));
    }

    // Check if password matches
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return next(new AppError('Invalid credentials', 401, ErrorCodes.INVALID_CREDENTIALS));
    }

    // Check if user is active
    if (!user.isActive) {
      return next(new AppError('Account is deactivated', 401, ErrorCodes.ACCOUNT_INACTIVE));
    }

    sendTokenResponse(user, 200, res);
  } catch (error) {
    next(error);
  }
};

// @desc    Logout user
// @route   POST /api/auth/logout
// @access  Private
export const logout = async (req, res, next) => {
  try {
    res
      .status(200)
      .cookie('token', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true
      })
      .cookie('refreshToken', 'none', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true
      })
      .json({
        success: true,
        message: 'Logged out successfully'
      });
  } catch (error) {
    next(error);
  }
};

// @desc    Get current logged in user
// @route   GET /api/auth/me
// @access  Private
export const getMe = async (req, res, next) => {
  try {
    const user = await User.findByPk(req.user.id);

    res.status(200).json({
      success: true,
      user: user.getPublicProfile()
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Refresh access token
// @route   POST /api/auth/refresh
// @access  Public
export const refreshToken = async (req, res, next) => {
  try {
    const { refreshToken } = req.body;


    if (!refreshToken) {
      return next(new AppError('Refresh token is required', 401, ErrorCodes.AUTH_TOKEN_MISSING));
    }

    const decoded = verifyRefreshToken(refreshToken);

    if (!decoded) {
      return next(new AppError('Invalid refresh token', 401, ErrorCodes.AUTH_TOKEN_INVALID));
    }

    const user = await User.findByPk(decoded.id);

    if (!user || !user.isActive) {
      return next(new AppError('User not found or inactive', 401, ErrorCodes.AUTH_TOKEN_INVALID));
    }

    const accessToken = generateAccessToken(user._id);

    res.status(200).json({
      success: true,
      accessToken,
      user: user.getPublicProfile()
    });
  } catch (error) {
    next(error);
  }
};


// @desc    Update user profile
// @route   PUT /api/auth/profile
// @access  Private
export const updateProfile = async (req, res, next) => {
  try {
    const { email, country } = req.body;

    const fieldsToUpdate = {};
    if (email) fieldsToUpdate.email = email;
    if (country) fieldsToUpdate.country = country;

    const user = await User.findByPk(req.user.id);
    await user.update(fieldsToUpdate);

    res.status(200).json({
      success: true,
      user: user.getPublicProfile()
    });
  } catch (error) {
    next(error);
  }
};

// @desc    Change password
// @route   PUT /api/auth/password
// @access  Private
export const changePassword = async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.scope('withPassword').findByPk(req.user.id);


    // Check current password
    const isMatch = await user.comparePassword(currentPassword);

    if (!isMatch) {
      return next(new AppError('Current password is incorrect', 401, ErrorCodes.INVALID_CREDENTIALS));
    }

    user.password = newPassword;
    await user.save();

    sendTokenResponse(user, 200, res);
  } catch (error) {
    next(error);
  }
};

