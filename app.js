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
    status: {
      code: Number,
      message: String
    }
  })
  User = mongoose.model('User', userSchema)
})

// view engine setup
app.set('views', path.join(__dirname, 'views'))
app.set('view engine', 'ejs')
app.use(express.static(path.join(__dirname, 'public')))

app.get('/', (req, res) => {
  res.render('index', {title: process.env.NAME})
})

// app.get('/auth/generate/:passkey', (req, res) => {
//   bcrypt.hash(req.params.passkey, parseInt(process.env.SALT_ROUNDS), (err, hash) => {
//     res.send(hash)
//   })
// })

app.get('/users', (req, res) => {
  User.find(function (err, users) {
    if (err) return console.error(err)
    res.render('users', {title: process.env.NAME, users: users})
  })
})

app.get('/auth/generate/:admin/:username', (req, res) => {
  bcrypt.compare(req.params.admin, process.env.ADMIN_HASH, (err, match) => {
    if (match) {
      let user = new User({
        name: req.params.username,
        key: uuid(),
        status: {
          code: 1,
          message: 'Valid Authenticated User'
        }
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
  User.findOne({key:req.params.key}, 'name status', (err, user) => {
    if (err) return res.status(400).json({code:400})
    if (user) return res.status(200).json({code:200, user: user.name, status: user.status})
    res.status(401).json({code:401})
  })
})

app.listen(process.env.PORT, () => {
  console.log(`[KEY-AUTH] Listening on *:${process.env.PORT}`)
})
