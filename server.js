const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const PORT = 5050
const path = require("path")

require('dotenv').config();

//require routes
const authorRoutes = require('./routes/authors');
const blogPostsRoutes = require('./routes/blogPosts');
const resourcesRoutes = require('./routes/resources');
const loginRoutes = require('./routes/login')
const githubRoutes = require('./routes/githubRoute')

const app = express();

app.use('/uploads', express.static(path.join(__dirname, '/uploads')));

//middleware
app.use(express.json());
app.use(cors());
//app.use('/uploads', express.static('uploads'));
//use routes
app.use('/', authorRoutes)
app.use('/', blogPostsRoutes)
app.use('/', resourcesRoutes)
app.use('/', loginRoutes)
app.use('/', githubRoutes)



mongoose.connect(process.env.MONGO_DB_URL)

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'Errore di connessione al server!'))
db.once('open', () => console.log('Database MongoDB connesso!'))



app.listen(PORT, () =>
    console.log(`Server avviato ed in ascolto sulla porta ${PORT}`)
)