/*
 * Copyright 2010-2013 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;

using System.Net;
using System.Net.Http;

using System.Xml;
using System.Text.RegularExpressions;

using Amazon.SecurityToken;
using Amazon.Runtime;
using Amazon.SecurityToken.Model;

// ******************* 2016/02/10 MZ **************************
// Use HtmlAgilityPack to Parse HTML
using HtmlAgilityPack;
// ******************* 2016/02/10 MZ **************************

namespace AWSSAML
{
    class AWSSAMLUtils
    {
        public string GetSamlAssertion(string identityProvider)
        {

            string samlAssertion = "";
            HttpWebResponse response = getResult(identityProvider);
            string responseStreamData;


            using (StreamReader reader = new StreamReader(response.GetResponseStream()))
            {
                responseStreamData = reader.ReadToEnd();
            }

            Regex reg = new Regex("SAMLResponse\\W+value\\=\\\"([^\\\"]+)\\\"");
            MatchCollection matches = reg.Matches(responseStreamData);
            string last = null;
            foreach (Match m in matches)
            {
                last = m.Groups[1].Value;
                samlAssertion = last;
            }

            return samlAssertion;
        }

        // ******************* 2016/02/10 MZ **************************
        public string GetSamlAssertionFormBasedMFA(string identityProvider, NetworkCredential credential, NetworkCredential additionalCredential)
        {

            string samlAssertion = "";
            string responseStreamData = getResultFormBasedMFA(identityProvider, credential, additionalCredential);

            Regex reg = new Regex("SAMLResponse\\W+value\\=\\\"([^\\\"]+)\\\"");
            MatchCollection matches = reg.Matches(responseStreamData);
            string last = null;
            foreach (Match m in matches)
            {
                last = m.Groups[1].Value;
                samlAssertion = last;
            }

            return samlAssertion;
        }
        // ******************* 2016/02/10 MZ **************************

        public string[] GetAwsSamlRoles(string samlAssertion)
        {
            string[] awsSamlRoles = null;
            XmlDocument doc = new XmlDocument();
            StringBuilder sb = new StringBuilder();
            StringWriter sw = new StringWriter(sb);
            byte[] decoded = Convert.FromBase64String(samlAssertion);
            string deflated = Encoding.UTF8.GetString(decoded);

            doc.LoadXml(deflated);       
            using (XmlTextWriter tw = new XmlTextWriter(sw) { Formatting = Formatting.Indented })
            {
                doc.WriteTo(tw);
            }

            XmlNamespaceManager nsmgr = new XmlNamespaceManager(doc.NameTable);
            nsmgr.AddNamespace("response", "urn:oasis:names:tc:SAML:2.0:assertion");
            string xPathString = "//response:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']";
            XmlNodeList roleAttributeNodes = doc.DocumentElement.SelectNodes(xPathString, nsmgr);

            if (roleAttributeNodes != null && roleAttributeNodes.Count > 0)
            {
                XmlNodeList roleNodes = roleAttributeNodes[0].ChildNodes;

                awsSamlRoles = new string[roleNodes.Count];

                for (int i = 0; i < roleNodes.Count; i++)
                {
                    XmlNode roleNode = roleNodes[i];
                    if (roleNode.InnerText.Length > 0)
                    {
                        string[] chunks = roleNode.InnerText.Split(',');
                        string newAwsSamlRole = chunks[0] + ',' + chunks[1];
                        awsSamlRoles[i] = newAwsSamlRole;
                    }
                }
            }

            return awsSamlRoles;
        }

        public SessionAWSCredentials GetSamlRoleCredentails(string samlAssertion, string awsRole)
        {
            string[] role = awsRole.Split(',');

            AssumeRoleWithSAMLRequest samlRequest = new AssumeRoleWithSAMLRequest();
            samlRequest.SAMLAssertion = samlAssertion;
            samlRequest.RoleArn = role[1];
            samlRequest.PrincipalArn = role[0];
            samlRequest.DurationSeconds = 3600;

            AmazonSecurityTokenServiceClient sts;
            AssumeRoleWithSAMLResponse samlResponse;
            try { 
                sts = new AmazonSecurityTokenServiceClient();
                samlResponse = sts.AssumeRoleWithSAML(samlRequest);
            }
            catch
            {
                sts = new AmazonSecurityTokenServiceClient("a", "b", "c");
                samlResponse = sts.AssumeRoleWithSAML(samlRequest);
            }

            SessionAWSCredentials sessionCredentials = new SessionAWSCredentials(
                samlResponse.Credentials.AccessKeyId,
                samlResponse.Credentials.SecretAccessKey,
                samlResponse.Credentials.SessionToken);

            return sessionCredentials;
        }

        private HttpWebResponse getResult(string url)
        {
            Uri uri = new Uri(url);

            CredentialCache credCache = new CredentialCache();
            credCache.Add(uri, "NTLM", CredentialCache.DefaultNetworkCredentials);

            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.UserAgent = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)";
            request.KeepAlive = true;
            request.Credentials = credCache;
            request.PreAuthenticate = true;
            request.AllowAutoRedirect = true;
            request.CookieContainer = new System.Net.CookieContainer();

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();

            return response;    
        }

        // ******************* 2016/02/10 MZ **************************
        // get Result using Form-based authentication to support MFA
        // return Response's StreamData instead of the HttpWebResponse
        private string getResultFormBasedMFA(string url, NetworkCredential credential, NetworkCredential additionalCredential)
        {
            Uri uri = new Uri(url);
            // Persistent cookies
            System.Net.CookieContainer myCookies = new System.Net.CookieContainer();
            // Query ADFS logon page to get initial session information
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(uri);
            request.UserAgent = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)";
            request.KeepAlive = true;
            // Try NTLM one more time anyway even though it might have failed in previous attempt. 
            CredentialCache credCache = new CredentialCache();
            credCache.Add(uri, "NTLM", CredentialCache.DefaultNetworkCredentials);
            request.Credentials = credCache;
            request.PreAuthenticate = true;
            request.AllowAutoRedirect = true;
            request.CookieContainer = myCookies;
            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            Stream responseStream = response.GetResponseStream();
            StreamReader responseStreamReader = new StreamReader(responseStream);
            string responseStreamData = responseStreamReader.ReadToEnd();

            // Check if default authentication with NTLM Impersonation worked or not
            // If it returns a SAML response
            if (responseStreamData.Contains("SAMLResponse"))
            {
                return responseStreamData;
            }
            // If it didn't return any SAM response, try form authentication
            else
            {
                //Parse HTML forms from previous response with HtmlAgilityPack
                HtmlDocument doc = new HtmlDocument();
                doc.LoadHtml(responseStreamData);
                HtmlNode rootNode = doc.DocumentNode;
                // map to hold the form input fields
                Dictionary<string, string> payloadData = new Dictionary<string, string>();
                foreach (HtmlNode node in rootNode.Descendants("input"))
                {
                    string input_name = node.Attributes["name"].Value;
                    string input_value = "";
                    if (node.Attributes["value"] != null)
                        input_value = node.Attributes["value"].Value;

                    if (input_name.ToLower().Contains("username"))
                    {
                        if (credential.Domain != null)
                        {
                            payloadData[input_name] = credential.Domain + "\\" + credential.UserName;
                        }
                        else
                        {
                            payloadData[input_name] = credential.UserName;
                        }
                    }
                    else if (input_name.ToLower().Contains("password"))
                    {
                        // Placeholder: Add logic to let user enter OTP again
                        
                        payloadData[input_name] = credential.Password;
                    }
                    else
                    {
                        if (payloadData.ContainsKey(input_name) && payloadData[input_name] != "" && input_value == "")
                        {
                            //DO nothing
                        }
                        else
                        {
                            payloadData[input_name] = input_value;
                        }
                    }
                }

                //Construct payload for Post
                string payload = "";
                foreach (string key in payloadData.Keys)
                {
                    payload += key + "=" + payloadData[key] + "&";
                }
                //Remove last &
                payload = payload.TrimEnd('&');
                request = (HttpWebRequest)WebRequest.Create(uri);
                request.CookieContainer = myCookies;
                request.ContentType = "application/x-www-form-urlencoded";
                request.Method = "POST";
                byte[] postData = Encoding.UTF8.GetBytes(payload);
                request.ContentLength = postData.Length;
                Stream postStream = request.GetRequestStream();
                postStream.Write(postData, 0, postData.Length);
                postStream.Close();

                response = (HttpWebResponse)request.GetResponse();
                responseStream = response.GetResponseStream();
                responseStreamReader = new StreamReader(responseStream);
                responseStreamData = responseStreamReader.ReadToEnd();

                // Check if response contains SAML Response or not
                // If it contains a SAML Response
                if (responseStreamData.Contains("SAMLResponse"))
                {
                    return responseStreamData;
                }
                // If it didn't contain any SAM response, let's check if it requires MFA
                else
                {
                    //Parse HTML forms from previous response with HtmlAgilityPack
                    doc = new HtmlDocument();
                    doc.LoadHtml(responseStreamData);
                    rootNode = doc.DocumentNode;
                    // map to hold the form input fields
                    payloadData = new Dictionary<string, string>();
                    foreach (HtmlNode node in rootNode.Descendants("input"))
                    {
                        string input_name = node.Attributes["name"].Value;
                        string input_value = "";
                        if (node.Attributes["value"] != null)
                            input_value = node.Attributes["value"].Value;

                        if (input_name.ToLower().Contains("password"))
                        {
                            if (additionalCredential.Password == null || additionalCredential.Password == "")
                                Console.WriteLine("Missing OTP.");
                             payloadData[input_name] = additionalCredential.Password;
                        }
                        else
                        {
                            if (payloadData.ContainsKey(input_name) && payloadData[input_name] != "" && input_value == "")
                            {
                                //DO nothing
                            }
                            else
                            {
                                payloadData[input_name] = input_value;
                            }
                        }
                    }

                    //Construct payload for Post
                    payload = "";
                    foreach (string key in payloadData.Keys)
                    {
                        payload += key + "=" + System.Web.HttpUtility.UrlEncode(payloadData[key]) + "&";
                    }
                    //Remove last &
                    payload = payload.TrimEnd('&');
                    request = (HttpWebRequest)WebRequest.Create(uri);
                    request.CookieContainer = myCookies;
                    request.ContentType = "application/x-www-form-urlencoded";
                    request.Method = "POST";
                    postData = Encoding.UTF8.GetBytes(payload);
                    request.ContentLength = postData.Length;
                    postStream = request.GetRequestStream();
                    postStream.Write(postData, 0, postData.Length);
                    postStream.Close();

                    response = (HttpWebResponse)request.GetResponse();
                    responseStream = response.GetResponseStream();
                    responseStreamReader = new StreamReader(responseStream);
                    responseStreamData = responseStreamReader.ReadToEnd();

                    // Check if response contains SAML Response or not
                    // If it contains a SAML Response
                    if (responseStreamData.Contains("SAMLResponse"))
                    {
                        return responseStreamData;
                    }
                    // If it didn't contain any SAM response, there was a problem ... 
                    else
                    {
                        // Do nothing and let the final return statement to return data as it is for possible debugging
                    }
                }
            }

            return responseStreamData;
        }
        // ******************* 2016/02/10 MZ **************************

    }
}
