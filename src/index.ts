import * as x509 from "@peculiar/x509";
import { Crypto } from "@peculiar/webcrypto";
import * as asn1js from "asn1js";
import { Convert } from "pvtsutils";
const pkijs = require("pkijs");
const MimeNode = require("emailjs-mime-builder").default;
const smimeParse = require("emailjs-mime-parser").default;

// Set crypto engine
const crypto = new Crypto()
const engineName = "@peculiar/webcrypto";
pkijs.setEngine(engineName, crypto, new pkijs.CryptoEngine({ name: engineName, crypto: crypto, subtle: crypto.subtle }));
x509.cryptoProvider.set(crypto);

interface Certificate {
  cert: string;
  key: string;
}

const encAlg = {
  name: "AES-CBC",
  length: 128,
};

const hashAlg = {
  name: "SHA-256"
};

async function createCertificate(alg: RsaHashedKeyGenParams): Promise<Certificate> {
  const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: "010203",
    name: "CN=Test, O=PeculiarVntures",
    notBefore: new Date(),
    notAfter: new Date(Date.now() + (24 * 60 * 60 * 1e3)),
    keys,
    signingAlgorithm: alg,
    extensions: [
      new x509.BasicConstraintsExtension(true, 3),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.cRLSign | x509.KeyUsageFlags.keyCertSign),
    ],
  });

  const pkcs8 = await crypto.subtle.exportKey("pkcs8", keys.privateKey);

  return {
    cert: cert.toString("pem"),
    key: x509.PemConverter.encode(pkcs8, "private key"),
  };
}

async function smimeEncrypt(cert: Certificate, content: string): Promise<string> {
  // Decode input certificate 
  const asn1 = asn1js.fromBER(x509.PemConverter.decode(cert.cert)[0]);
  const certSimpl = new pkijs.Certificate({ schema: asn1.result });

  const cmsEnveloped = new pkijs.EnvelopedData();

  cmsEnveloped.addRecipientByCertificate(certSimpl, { oaepHashAlgorithm: hashAlg.name });

  await cmsEnveloped.encrypt(encAlg, Convert.FromUtf8String(content));

  const cmsContentSimpl = new pkijs.ContentInfo();
  cmsContentSimpl.contentType = "1.2.840.113549.1.7.3";
  cmsContentSimpl.content = cmsEnveloped.toSchema();

  const schema = cmsContentSimpl.toSchema();
  const ber = schema.toBER(false);

  // Insert enveloped data into new Mime message
  const mimeBuilder = new MimeNode("application/pkcs7-mime; name=smime.p7m; smime-type=enveloped-data; charset=binary")
    .setHeader("content-description", "Enveloped Data")
    .setHeader("content-disposition", "attachment; filename=smime.p7m")
    .setHeader("content-transfer-encoding", "base64")
    .setContent(new Uint8Array(ber));
  mimeBuilder.setHeader("from", "sender@example.com");
  mimeBuilder.setHeader("to", "recipient@example.com");
  mimeBuilder.setHeader("subject", "Example S/MIME encrypted message");

  return mimeBuilder.build();
}

async function smimeDecrypt(cert: Certificate, smime: string) {
  // Decode input certificate
  let asn1 = asn1js.fromBER(x509.PemConverter.decode(cert.cert)[0]);
  const certSimpl = new pkijs.Certificate({ schema: asn1.result });

  // Decode input private key 
  const privateKeyBuffer = x509.PemConverter.decode(cert.key)[0];

  // Parse S/MIME message to get CMS enveloped content 
  const parser = smimeParse(smime);

  // Make all CMS data
  asn1 = asn1js.fromBER(parser.content.buffer);
  if (asn1.offset === (-1)) {
    alert("Unable to parse your data. Please check you have \"Content-Type: charset=binary\" in your S/MIME message");
    return;
  }

  const cmsContentSimpl = new pkijs.ContentInfo({ schema: asn1.result });
  const cmsEnvelopedSimpl = new pkijs.EnvelopedData({ schema: cmsContentSimpl.content });

  const message = await cmsEnvelopedSimpl.decrypt(0, {
    recipientCertificate: certSimpl,
    recipientPrivateKey: privateKeyBuffer
  });

  return Convert.ToUtf8String(message);
}

async function main() {
  const cert = await createCertificate({
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
  });

  // Print certificate
  console.log("Certificate:");
  console.log(cert.cert);
  console.log();

  // Print private key
  console.log("Private key:");
  console.log(cert.key);
  console.log();

  const smime = await smimeEncrypt(cert, "Some message");
  console.log("S/MIME message:");
  console.log(smime);
  console.log();

  const smimeMessage = await smimeDecrypt(cert, smime);
  console.log("Decrypted message:", smimeMessage)
}

main().catch(e => console.error(e));