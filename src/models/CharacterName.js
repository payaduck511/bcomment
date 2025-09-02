// models/CharacterName.js
const mongoose = require('mongoose');

const characterNameSchema = new mongoose.Schema({
    ocid: { type: String, required: true, unique: true },
    character_name: { type: String, required: true }
});

const CharacterName = mongoose.model('CharacterName', characterNameSchema);

module.exports = CharacterName;