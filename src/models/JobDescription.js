const mongoose = require('mongoose');

const jobDescriptionSchema = new mongoose.Schema({
    jobName: { type: String, required: true, unique: true },
    description: { type: String, required: true }
});

module.exports = mongoose.model('JobDescription', jobDescriptionSchema);