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

import java.security.Principal;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 *
 * @author theuns
 */
public class JwtServletRequestWrapper extends HttpServletRequestWrapper {

    AuthProvider provider;

    public JwtServletRequestWrapper(HttpServletRequest request) {
        super(request);
        provider = new AuthProvider(request);

        //provider.s
    }

    @Override
    public Principal getUserPrincipal() {
        if (provider.isValidToken()) {
            return new JwtPrincipal(provider.getToken());
        } else {
            return super.getUserPrincipal(); //To change body of generated methods, choose Tools | Templates.
        }
    }

    @Override
    public boolean isUserInRole(String role) {
        if (provider.isValidToken()) {
            TokenClaim c = provider.getToken().getClaim(TokenClaim.class);
            if (c.getRoles() != null) {
                for (String r : c.getRoles()) {
                    if (r.equalsIgnoreCase(role)) {
                        return true;
                    }
                }
            }
            return false;
        }
        return super.isUserInRole(role); //To change body of generated methods, choose Tools | Templates.
    }

}
