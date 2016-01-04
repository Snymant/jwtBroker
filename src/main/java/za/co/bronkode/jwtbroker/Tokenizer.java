/*
 * The MIT License
 *
 * Copyright 2015 Theuns Snyman.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package za.co.bronkode.jwtbroker;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author theuns
 */
public class Tokenizer {

    private static String privateKey;
    private static String issuer;
    private static int expiryMinutes;
    private static Class claimClass;

    public static void setPrivateKey(String privateKey) {
        Tokenizer.privateKey = privateKey;
    }
    
    public static void setIssuer(String issuer){
        Tokenizer.issuer =issuer;
    }
    
    public static void setExpirtyMinutes(int expiryMinutes){
        Tokenizer.expiryMinutes = expiryMinutes;
    }

    public static Class getClaimClass() {
        return claimClass;
    }

    public static void setClaimClass(Class claimClass) {
        Tokenizer.claimClass = claimClass;
    }

    public static Token DecodeToken(String token) {
        if (IsValidToken(token)) {
            try {
                String[] items = token.split("\\.");

                Token t = new Token();

                ObjectMapper mapper = new ObjectMapper();
                byte[] headerBytes = Base64.getDecoder().decode(items[0]);
                byte[] claimBytes = Base64.getDecoder().decode(items[1]);
                String headerjson = new String(headerBytes);
                String claimjson = new String(claimBytes);
                t.setHeader(mapper.readValue(headerjson, TokenHeader.class));
                t.setClaim(mapper.readValue(claimjson, claimClass));

                return t;
            } catch (IOException ex) {
                Logger.getLogger(Tokenizer.class.getName()).log(Level.SEVERE, null, ex);

            }
        } else {
            return null;
        }
        return null;
    }

    public static boolean IsValidToken(String token) {
        //header.claim.sign
        String[] items = token.split("\\.");
        if (items.length != 3) {
            return false;
        }
        String h64 = items[0];
        String c64 = items[1];
        String signature = items[2];
        String verifiedSignature = GetSignature(h64, c64);
        return verifiedSignature.equals(signature);
    }

    public static String EncodeToken(Token token) {
        try (StringWriter hwriter = new StringWriter();
                StringWriter cwriter = new StringWriter();) {
            ObjectMapper hmapper = new ObjectMapper();

            hmapper.writeValue(hwriter, token.getHeader());
            String header = hwriter.toString();
            hmapper.writeValue(cwriter, token.getClaim(claimClass));
            String claim = cwriter.toString();
            hwriter.close();
            cwriter.close();
            String h64 = Base64.getEncoder().encodeToString(header.getBytes());
            String c64 = Base64.getEncoder().encodeToString(claim.getBytes());
            String signature = GetSignature(h64, c64);
            StringBuilder sb = new StringBuilder(h64);
            sb.append(".");
            sb.append(c64);
            sb.append(".");
            sb.append(signature);
            return sb.toString();
        } catch (IOException ex) {
            Logger.getLogger(Tokenizer.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    public static String GetSignature(String header, String claim) {
        try {

            StringBuilder sb = new StringBuilder(header);
            sb.append(".");
            sb.append(claim);
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKey key = new SecretKeySpec(privateKey.getBytes(), "HmacSHA256");

            mac.init(key);
            String signature = Base64.getEncoder().encodeToString(mac.doFinal(sb.toString().getBytes()));
            return signature;
        } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
            Logger.getLogger(Tokenizer.class.getName()).log(Level.SEVERE, null, ex);
        }
        return "";
    }

    public static <T extends TokenClaim> T getNewClaim() throws InstantiationException, IllegalAccessException {
        T claim;
        claim = (T)claimClass.newInstance();
        claim.setIss(issuer);
        claim.setIat(System.currentTimeMillis());
        claim.setExp(expiryMinutes *60*1000);
        return claim;
    }

}
