const path = require('path')
const express = require('express')
const morgan = require('morgan')
const app = express()
module.exports = app


app.engine('html', require('ejs').renderFile);

// logging middleware
app.use(morgan('dev'))

// body parsing middleware
app.use(express.json())

const { models: { User }} = require('./db');

app.get('/api/github/callback', async(req, res, next)=> {
  try {
    const token = await User.authenticateWithGithub(req.query.code);
    res.send(`
      <html>
        <script>
        window.localStorage.setItem('token', '${ token }');
        window.document.location = '/';
        </script>
      </html>
    `);

  }
  catch(ex){
    next(ex);

  }
});

// auth and api routes
app.use('/auth', require('./auth'))
app.use('/api', require('./api'))


const returnHomePage = (req, res) => {
  res.render(path.join(__dirname, '..', 'public/index.html'), { client_id: process.env.client_id });
}

app.get('/', returnHomePage); 

// static file-serving middleware
app.use(express.static(path.join(__dirname, '..', 'public')))

// any remaining requests with an extension (.js, .css, etc.) send 404
app.use((req, res, next) => {
  if (path.extname(req.path).length) {
    const err = new Error('Not found')
    err.status = 404
    next(err)
  } else {
    next()
  }
})

// sends index.html
app.use('*', returnHomePage)

// error handling endware
app.use((err, req, res, next) => {
  console.error(err)
  console.error(err.stack)
  res.status(err.status || 500).send(err.message || 'Internal server error.')
})
