const mongoose = require('mongoose');

const likeSchema = new mongoose.Schema({
  commentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Comment', required: true },
  username: { type: String, required: true },
  likedAt: { type: Date, default: Date.now },
});

likeSchema.index({ commentId: 1, username: 1 }, { unique: true }); // 중복 추천 방지

const Like = mongoose.model('Like', likeSchema);

module.exports = Like;