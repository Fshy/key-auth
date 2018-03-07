const bcrypt      = require('bcrypt')
const uuid        = require('uuid/v4')
const dotenv      = require('dotenv').config()
const path        = require('path')
const express     = require('express')
const mongoose    = require('mongoose')
const app         = express()

const mongoDB     = `mongodb://${process.env.DB_HOST}/${process.env.DB_NAME}`

mongoose.connect(mongoDB)
let db = mongoose.connection
let User

db.on('error', console.error.bind(console, 'connection error:'))

db.once('open', () => {
  console.log(`Connected to DB`)
  let userSchema = mongoose.Schema({
    name: String,
    key: String,
    timestamp: Date,
    flag: Number
  })
  User = mongoose.model('User', userSchema)
})

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.use(express.static(path.join(__dirname, 'public')))

app.get('/', (req, res) => {
  User.find(function (err, users) {
    if (err) return console.error(err)
    for (var i = 0; i < users.length; i++) {
      switch (users[i].flag) {
        case 0:
          users[i].message = 'Subscription Pending Activation'
          break
        case 1:
          users[i].message = 'Subscription Active'
          break
        case 2:
          users[i].message = 'Subscription Expired/Terminated'
          break
        default:
          users[i].message = 'Unhandled User Flag; Contact Support'
          break
      }
    }
    res.render('users', {title: process.env.NAME, users: users})
  })
})

// app.get('/auth/generate/:passkey', (req, res) => {
//   bcrypt.hash(req.params.passkey, parseInt(process.env.SALT_ROUNDS), (err, hash) => {
//     res.send(hash)
//   })
// })

app.get('/auth/generate/:admin/:username', (req, res) => {
  bcrypt.compare(req.params.admin, process.env.ADMIN_HASH, (err, match) => {
    if (match) {
      let user = new User({
        name: req.params.username,
        key: uuid(),
        timestamp: Date.now(),
        flag: 0,
      })
      user.save().then(() => {
        res.send(user.key)
      })
    }else {
      res.sendStatus(403)
    }
  })
})

app.get('/auth/check/:key', (req, res) => {
  console.log(`Attempting to authorize key: ${req.params.key}`)
  User.findOne({key:req.params.key}, (err, user) => {
    if (err) return res.status(400).json({code:400, message: 'Bad Request'})
    if (user) {
      switch (user.flag) {
        case 0:   return res.status(401).json({code:401, id: user.id, username: user.name, key: user.key, timestamp: user.timestamp, flag: user.flag, message: 'Subscription Pending Activation'})
        case 1:   return res.status(200).json({code:200, id: user.id, username: user.name, key: user.key, timestamp: user.timestamp, flag: user.flag, message: 'Subscription Active'})
        case 2:   return res.status(401).json({code:401, id: user.id, username: user.name, key: user.key, timestamp: user.timestamp, flag: user.flag, message: 'Subscription Expired/Terminated'})
        default:  return res.status(401).json({code:401, id: user.id, username: user.name, key: user.key, timestamp: user.timestamp, flag: user.flag, message: 'Unhandled User Flag; Contact Support'})
      }
    }
    res.status(401).json({code:401, message: 'Invalid API Key'})
  })
})

app.get('/auth/update/:admin/:id/:flag', (req, res) => {
  bcrypt.compare(req.params.admin, process.env.ADMIN_HASH, (err, match) => {
    if (match) {
      User.findById(req.params.id, (err, user) => {
        if (err) return res.status(400).json({code:400, message: 'ID Not Found'})
        user.flag = parseInt(req.params.flag)
        user.save(() => {
          if (err) return res.status(400).json({code:400, message: 'Failed to Update Record'})
          res.status(200).json({code:200, id: user.id, username: user.name, key: user.key, timestamp: user.timestamp, flag: user.flag, message: 'Sucessfully Updated User Record'})
        })
      })
    }else {
      res.sendStatus(403)
    }
  })
})

app.listen(process.env.PORT, () => {
  console.log(`[KEY-AUTH] Listening on *:${process.env.PORT}`)
})
