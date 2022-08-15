const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
require('dotenv').config()

app.use(express.json());

let refreshTokens = []

app.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.token);
    res.status(204)
})

app.post('/token', () => {
    const refreshToken = req.body.token;
    if (refreshToken == null) return res.status(401);
    if (!refreshTokens.includes(refreshToken)) return res.status(403)

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403);
        const accessToken = generateAccessToken({ name: user.name });
        res.json({
            accessToken: accessToken
        })
    })
})

app.post('/login', AuthenticateToken, (req, res) => {
    const username = req.body.username;
    const user = { name: username };


    const accessToken = generateAccessToken(user);
    const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
    refreshTokens.push(refreshToken);
    res.json({ accessToken: accessToken, refreshToken: refreshToken })

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

function generateAccessToken(user) {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15s' })
}

app.listen(4000)