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

/*
Setup filter in web.xml:
 <filter>
        <filter-name>LogFilter</filter-name>
        <filter-class>za.co.bronkode.jwtbroker</filter-class>
        <init-param>
            <param-name>test-param</param-name>
            <param-value>Initialization Paramter</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>LogFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>
*/
package za.co.bronkode.jwtbroker;

import javax.servlet.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpServletRequest;

/**
 *
 * @author ts
 */
// Implements Filter class
public class JwtFilter implements Filter {

    @Override
    public void init(FilterConfig config)
            throws ServletException {
        // Get init parameter
        Enumeration<String> initParameterNames = config.getInitParameterNames();
        String privateKey = config.getInitParameter("privateKey");
        String issuer = config.getInitParameter("issuer");
        String configMinutes = config.getInitParameter("expiryMinutes");
        int expirtyMinutes = 10;
        if(configMinutes != null)
              expirtyMinutes = Integer.parseInt(configMinutes);
        Tokenizer.setPrivateKey(privateKey);
        Tokenizer.setIssuer(issuer);
        //Tokenizer.setExpirtyMinutes(expirtyMinutes);
        try {
            Tokenizer.setClaimClass(Class.forName(config.getInitParameter("claimClass")));
        } catch (ClassNotFoundException ex) {
            ex.addSuppressed(new Exception("Defaulting to " +TokenClaim.class.toString() ));
            Logger.getLogger(JwtFilter.class.getName()).log(Level.SEVERE, null, ex);
            Tokenizer.setClaimClass(TokenClaim.class);
            
        }
    }

    @Override
    public void doFilter(ServletRequest request,
            ServletResponse response,
            FilterChain chain)
            throws java.io.IOException, ServletException {

        
        //Log the IP of client machine
        //String ipAddress = request.getRemoteAddr();
        
       //we accept auth token in header or as request parameter.
        Map<String, String[]> parameterMap = request.getParameterMap();
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        String header = httpRequest.getHeader("Authorization");        
        if (header != null) {            
            //We store the raw text in request attribute
            request.setAttribute("authTokenText", header);           
        }//header not suppled so check url parameters
        else{
            if(parameterMap.containsKey("jwttoken")){
                String jt =  parameterMap.get("jwttoken")[0];
                //jt = jt.replace(" ", "+");
                request.setAttribute("authTokenText", jt);           
            }
        }        
        
        System.out.println("JWT Filter hit!");

        // Pass request back down the filter chain      
        chain.doFilter(request, response);

    }

    @Override
    public void destroy() {
        /* Called before the Filter instance is removed 
         from service by the web container*/
    }
}
