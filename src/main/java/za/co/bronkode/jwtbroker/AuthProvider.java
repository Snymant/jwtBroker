/*
 * The MIT License
 *
 * Copyright 2016 theuns.
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

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

/**
 *
 * @author theuns
 */
@RequestScoped
public class AuthProvider {

    @Inject
    HttpServletRequest request;

    private boolean validToken;
    private Token token;

    public AuthProvider() {
    }

    public AuthProvider(HttpServletRequest request) {
        this.request = request;
    }
    
    

    public boolean isValidToken() {
        return validToken;
    }

    public void setValidToken(boolean validToken) {
        this.validToken = validToken;
    }

    public Token getToken() {
        return token;
    }

    public void setToken(Token token) {
        this.token = token;
    }

    @PostConstruct
    public void init() {

        Object awt = request.getAttribute("authTokenText");
        this.validToken = false;
        if (awt != null && (awt instanceof String)) {
            String headerToken = awt.toString();
            Token decodedToken = Tokenizer.DecodeToken(headerToken);
            if(decodedToken !=null){
                //TODO: check expiry
                this.token = decodedToken;
                this.validToken = true;
            }
        }

    }

}
