import express from 'express'

import {createUser, getUserByEmail} from '../db/users'
import {random, authentication} from '../helpers'

export const login = async (req: express.Request, res: express.Response) => {
  try {
    const {email, password} = req.body

    // If missing any of the field, send 400
    if (!email || !password) {
      return res.sendStatus(400)
    }

    const user = await getUserByEmail(email).select('+authentication.salt + authentication.password')

    // If user is missing, also send 400
    if (!user) {
      return res.sendStatus(400)
    }

    const expectedHash = authentication(user.authentication.salt, password)
    if (user.authentication.password !== expectedHash) {
      return res.sendStatus(403)
    }

    const salt = random()
    user.authentication.sessionToken = authentication(salt, user._id.toString())

    await user.save()

    res.cookie('MY-AUTH', user.authentication.sessionToken, {
      domain: 'localhost',
      path: '/'
    })
    return res.sendStatus(200).json(user).end()

  } catch (error) {
    console.log(error)
    return res.sendStatus(400)
  }
}

export const register = async(req: express.Request, res: express.Response) => {
  try {
    const {username, email, password} = req.body

    // If missing any of the field, send 400
    if (!email || !password || !username) {
      return res.sendStatus(400)
    }

    // If input email already exist, also send 400
    const existingUser = await getUserByEmail(email)
    if (existingUser) {
      return res.sendStatus(400)
    }

    // Otherwise if everything is working
    const salt = random()
    const user  = await createUser({
      username,
      email,
      authentication: {
        salt,
        password: authentication(salt, password)
      }
    })
    return res.status(200).json(user).end()


  } catch (error) {
    console.log(error)
    return res.sendStatus(400)
  }



}