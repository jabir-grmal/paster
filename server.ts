import express from "express";
import { createServer as createViteServer } from "vite";
import nodemailer from "nodemailer";
import dns from "dns";
import net from "net";

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '10mb' }));

  // API route for SMTP validation
  app.post("/api/validate", async (req, res) => {
    const { host, port, user, pass, secure } = req.body;

    if (!host || !port || !user || !pass) {
      return res.status(400).json({ success: false, error: "Missing credentials" });
    }

    const transporter = nodemailer.createTransport({
      host,
      port: parseInt(port),
      secure: secure || port === 465, // true for 465, false for other ports
      auth: {
        user,
        pass,
      },
      connectionTimeout: 10000, // 10 seconds timeout
      greetingTimeout: 10000,
      socketTimeout: 10000,
    });

    try {
      await transporter.verify();
      res.json({ success: true });
    } catch (error: any) {
      res.json({ success: false, error: error.message });
    } finally {
      transporter.close();
    }
  });

  // API route for Email Existence Verification (Deep Check)
  app.post("/api/verify-email", async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ success: false, error: "Email required" });

    const domain = email.split('@')[1];
    if (!domain) return res.json({ success: false, error: "Invalid domain" });

    try {
      // 1. Get MX records
      const mxRecords = await new Promise<dns.MxRecord[]>((resolve, reject) => {
        dns.resolveMx(domain, (err, records) => {
          if (err || !records || records.length === 0) resolve([]);
          else resolve(records.sort((a, b) => a.priority - b.priority));
        });
      });

      if (mxRecords.length === 0) {
        return res.json({ success: false, error: "No MX records found" });
      }

      const mxHost = mxRecords[0].exchange;

      // 2. Attempt SMTP Handshake (Basic check)
      const socket = net.createConnection(25, mxHost);
      socket.setTimeout(10000); // Increased timeout

      let step = 0;
      let result = { success: false, error: "Verification failed" };

      socket.on('data', (data) => {
        const response = data.toString();
        const code = parseInt(response.substring(0, 3));

        if (step === 0 && code === 220) {
          socket.write(`EHLO ${domain}\r\n`);
          step++;
        } else if (step === 1 && (code === 250 || code === 220)) {
          socket.write(`MAIL FROM:<admin@${domain}>\r\n`);
          step++;
        } else if (step === 2 && code === 250) {
          socket.write(`RCPT TO:<${email}>\r\n`);
          step++;
        } else if (step === 3) {
          if (code === 250 || code === 251) {
            result = { success: true, error: "" };
          } else {
            result = { success: false, error: `Server responded with ${code}: ${response.split('\r\n')[0]}` };
          }
          socket.write(`QUIT\r\n`);
          socket.end();
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        res.json({ success: false, error: "Connection timeout" });
      });

      socket.on('error', (err) => {
        res.json({ success: false, error: err.message });
      });

      socket.on('close', () => {
        if (!res.headersSent) res.json(result);
      });

    } catch (error: any) {
      if (!res.headersSent) res.json({ success: false, error: error.message });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static("dist"));
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
