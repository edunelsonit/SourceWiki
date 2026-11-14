import express from 'express';
import {
  register,
  login,
  logout,
  getMe,
  refreshToken,
  updateProfile,
  changePassword,
  startWikimediaLogin,
  wikimediaCallback,
  exchangeWikimediaSession
} from '../controllers/authController.js';
import { protect } from '../middleware/auth.js';
import { registerValidation, loginValidation, validate } from '../middleware/validator.js';

const router = express.Router();

router.post('/register', registerValidation, validate, register);
router.post('/login', loginValidation, validate, login);
router.post('/logout', protect, logout);
router.get('/me', protect, getMe);
router.post('/refresh', refreshToken);
router.put('/profile', protect, updateProfile);
router.put('/password', protect, changePassword);
router.get('/wikimedia', startWikimediaLogin);
router.get('/wikimedia/callback', wikimediaCallback);
router.post('/wikimedia/session', exchangeWikimediaSession);

export default router;
