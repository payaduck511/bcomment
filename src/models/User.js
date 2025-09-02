const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

// 사용자 스키마 정의
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    nickname: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    lastCommentAt: { type: Date, default: null },
    verificationCode: { type: String }, // 인증 코드 필드
    verificationExpires: { type: Date },
    resetPasswordCode: { type: String }, // 여기 필드 이름 수정
    resetPasswordExpires: { type: Date },
    lastLogin: { type: Date, default: Date.now },
    isAdmin: { type: Boolean, default: false }
});

// 비밀번호를 저장하기 전에 암호화하는 미들웨어
userSchema.pre('save', async function (next) {
    const user = this;

    // 비밀번호가 변경되었거나 새로 생성된 경우만 암호화
    if (user.isModified('password')) {
        try {
            // 이미 해시된 비밀번호가 아닌 경우에만 해시화 수행
            if (!user.password.startsWith('$2b$')) {
                const salt = await bcrypt.genSalt(10);
                user.password = await bcrypt.hash(user.password, salt);
            }
            next();
        } catch (error) {
            next(error);
        }
    } else {
        return next();
    }
});

// 비밀번호 비교 메서드
userSchema.methods.comparePassword = async function (inputPassword) {
    return bcrypt.compare(inputPassword, this.password);
};

// 마지막 로그인 시간 업데이트 메서드
userSchema.methods.updateLastLogin = function () {
    this.lastLogin = Date.now();
    return this.save();
};

// 사용자 모델 생성
const User = mongoose.model('User', userSchema);

module.exports = User;