import express from 'express';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import crypto from 'crypto';


dotenv.config();
const app = express();


app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));




function generateSignature(req, res, next) {
    const signature = crypto
      .createHmac("sha256", process.env.SECRET_KEY)
      .update(JSON.stringify(req.body))
      .digest("hex");
    req.signature = signature;
    next();
}


function verifySignature(req, res, next) {
    const signature = req.headers["x-signature"];
    const timestamp = req.headers["x-timestamp"];

    if (!signature) {
      return res.status(401).json({ error: "Unauthorized: missing signature" });
    }

  
    const payloadBuffer = req.rawBody || Buffer.from(JSON.stringify(req.body));
    const expectedSignature = crypto
      .createHmac("sha256", process.env.SECRET_KEY)
      .update(timestamp + req.rawBody)
      .digest("hex");
  
    console.log("Signature received:", signature);
    console.log("Signature expected:", expectedSignature);
  
    if (signature !== expectedSignature) {
      return res.status(401).json({ error: "Unauthorized: invalid signature" });
    }
  
    next();
  }

// Create a transporter for sending emails
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: true,
    auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
    },
    logger: true,
    debug: true,
});



app.post('/generate-signature', generateSignature, (req, res, next) => {
    res.json({signature: req.signature});
    next();
});

// Route to send emails
app.post('/send-email', verifySignature, (req, res) => {
    const { to, subject, html } = req.body;
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to,
        subject,
        html,
    };
    transporter.sendMail(mailOptions, (error, info) => {
        if(error){
            return res.status(500).json({
                error: 'Failed to send email',
                code: error.code,
                command: error.command,
                response: error.response,
                responseCode: error.responseCode,
            });
        }
        res.json({message: 'Email sent successfully'});
    });
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


export default app; 