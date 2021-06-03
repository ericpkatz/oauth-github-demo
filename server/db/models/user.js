const Sequelize = require('sequelize')
const db = require('../db')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt');
const axios = require('axios');

const SALT_ROUNDS = 5;

const User = db.define('user', {
  username: {
    type: Sequelize.STRING,
    unique: true,
    allowNull: false
  },
  password: {
    type: Sequelize.STRING,
  },
  githubId: {
    type: Sequelize.INTEGER
  }
})

module.exports = User

/**
 * instanceMethods
 */
User.prototype.correctPassword = function(candidatePwd) {
  //we need to compare the plain version to an encrypted version of the password
  return bcrypt.compare(candidatePwd, this.password);
}

User.prototype.generateToken = function() {
  return jwt.sign({id: this.id}, process.env.JWT)
}

/**
 * classMethods
 */
User.authenticate = async function({ username, password }){
    const user = await this.findOne({where: { username }})
    if (!user || !(await user.correctPassword(password))) {
      const error = Error('Incorrect username/password');
      error.status = 401;
      throw error;
    }
    return user.generateToken();
};

User.authenticateWithGithub = async function(code){
  let response = await axios.post( 'https://github.com/login/oauth/access_token', {
    code: code,
    client_id: process.env.client_id,
    client_secret: process.env.client_secret
  }, {
    headers: {
      accept: 'application/json'
    }
  });

  const data = response.data;
  console.log(data);
  if(data.error){
    const error = Error(data.error);
    error.status = 401;
    throw error;
  }

  response = await axios.get('https://api.github.com/user', {
    headers: {
      Authorization: `token ${data.access_token}`
    }
  });

  const { login, id } = response.data;
  let user = await User.findOne({
    where: { githubId: id }
  });
  if(!user){
    user = await User.create({
      githubId: id,
      username: login
    });
  }
  return user.generateToken();
}

User.findByToken = async function(token) {
  try {
    const {id} = await jwt.verify(token, process.env.JWT)
    const user = User.findByPk(id)
    if (!user) {
      throw 'nooo'
    }
    return user
  } catch (ex) {
    const error = Error('bad token')
    error.status = 401
    throw error
  }
}

/**
 * hooks
 */
const hashPassword = async(user) => {
  //in case the password has been changed, we want to encrypt it with bcrypt
  if (user.changed('password')) {
    user.password = await bcrypt.hash(user.password, SALT_ROUNDS);
  }
}

User.beforeCreate(hashPassword)
User.beforeUpdate(hashPassword)
User.beforeBulkCreate(users => Promise.all(users.map(hashPassword)))
