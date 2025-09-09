const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
    job: { type: String }, // 특정 직업명 저장 (직업별 댓글일 경우)
    character_id: { type: String }, // 캐릭터 ID (캐릭터별 댓글일 경우)
    username: { type: String, required: true }, // 댓글 작성자
    content: { type: String, required: true }, // 댓글 내용
    createdAt: { type: Date, default: Date.now }, // 댓글 작성 시간
    likes: { type: Number, default: 0 } // 추천 수
});

const Comment = mongoose.model('Comment', commentSchema);

module.exports = Comment;