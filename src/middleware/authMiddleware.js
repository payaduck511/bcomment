const jwt = require('jsonwebtoken');
const User = require('../models/User'); // User 모델 임포트 (경로에 따라 조정 필요)

// 사용자 인증 미들웨어
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    console.log('Authorization header:', authHeader);

    if (!authHeader) {
        console.log('Authorization header is missing');
        return res.status(401).json({ message: 'Authorization header is missing' });
    }

    const token = authHeader.split(' ')[1];
    if (token == null) {
        console.log('Token is missing');
        return res.status(401).json({ message: 'Token is missing' });
    }

    console.log('Token received:', token);
    jwt.verify(token, process.env.JWT_SECRET, async (err, decodedToken) => {
        if (err) {
            if (err.name === 'TokenExpiredError') {
                console.log('Token has expired');
                return res.status(403).json({ message: 'Token has expired' });
            }
            console.log('Invalid token:', err.message);
            return res.status(403).json({ message: 'Invalid token' });
        }

        console.log('Decoded token:', decodedToken);

        try {
            // 데이터베이스에서 사용자 정보 가져오기
            const user = await User.findOne({ username: decodedToken.username });

            if (!user) {
                console.log('User not found in database');
                return res.status(401).json({ message: 'User not found' });
            }

            console.log('User authenticated:', user);
            req.user = user; // 데이터베이스에서 가져온 사용자 객체를 req.user에 저장
            next();
        } catch (error) {
            console.error('Error fetching user from database:', error);
            return res.status(500).json({ message: 'Server error' });
        }
    });
}

// 관리자 권한 미들웨어
function isAdmin(req, res, next) {
    if (req.user && req.user.isAdmin) {
        next();
    } else {
        res.status(403).json({ message: '관리자 권한이 필요합니다.' });
    }
}

module.exports = { authenticateToken, isAdmin };