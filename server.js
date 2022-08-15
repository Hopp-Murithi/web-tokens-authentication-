const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
require('dotenv').config()

app.use(express.json());

const posts = [{
        username: "Hopp",
        title: "Sir1"
    },
    {
        username: "Neema",
        title: "Madam2"
    }
]

app.get('/posts', (req, res) => {
    res.json(posts.filter(post => post.username === req.user.name))

})

function AuthenticateToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
    if (token == null) return res.status(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403);
        req.user = user
        next()
    })

}

app.listen(3000)