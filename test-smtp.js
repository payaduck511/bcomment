// .env 파일의 환경 변수를 불러옵니다.
require('dotenv').config();
const nodemailer = require('nodemailer');

// 1. app.js에 있는 것과 동일한 transporter를 설정합니다.
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER, // .env 파일의 GMAIL_USER
    pass: process.env.GMAIL_APP_PASSWORD, // .env 파일의 GMAIL_APP_PASSWORD
  },
});

// 2. 테스트 이메일을 보내는 함수를 만듭니다.
async function runTest() {
  console.log('Attempting to connect to SMTP server...');

  try {
    // 2-1. SMTP 서버 연결 확인 (verify)
    await transporter.verify();
    console.log('✅ Connection to SMTP server was successful.');

    // 2-2. 실제 테스트 이메일 발송
    console.log('Sending a test email...');
    const info = await transporter.sendMail({
      from: `"SMTP Test" <${process.env.GMAIL_USER}>`, // 보내는 사람
      to: process.env.GMAIL_USER, // 받는 사람 (자기 자신에게 테스트)
      subject: '✅ Nodemailer SMTP Test Successful', // 제목
      text: 'This is a test email sent from the Node.js script.', // 내용
    });

    console.log('✅ Test email sent successfully!');
    console.log('Message ID:', info.messageId);

  } catch (error) {
    console.error('❌ An error occurred during the SMTP test:');
    console.error(error); // 가장 중요한 에러 정보
  }
}

// 3. 테스트 함수를 실행합니다.
runTest();