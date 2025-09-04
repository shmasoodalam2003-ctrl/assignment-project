import express from 'express'
import { getUserProfile } from '../routes/userProfile'

const router = express.Router()

// Correct way
router.get('/', getUserProfile)

export default router
