﻿using System;
using System.Net;

namespace threatexpertchecker
{
    /// <summary>
    /// 
    /// </summary>
    public class WebClientResult
    {
        public string Response { get; set; }
        public bool IsError { get; set; }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="response"></param>
        /// <param name="isError"></param>
        public WebClientResult(string response,
                               bool isError)
        {
            Response = response;
            IsError = isError;
        }
    }

    /// <summary>
    /// 
    /// </summary>
    public class GZipWebClient : WebClient
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="address"></param>
        /// <returns></returns>
        protected override WebRequest GetWebRequest(Uri address)
        {
            HttpWebRequest request = (HttpWebRequest)base.GetWebRequest(address);
            request.AutomaticDecompression = DecompressionMethods.GZip |
                                             DecompressionMethods.Deflate;
            request.UserAgent = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1468.0 Safari/537.36";

            IWebProxy defaultProxy = WebRequest.GetSystemWebProxy();
            Uri uriProxy = defaultProxy.GetProxy(address);
            if (uriProxy.AbsoluteUri != string.Empty)
            {
                request.Proxy = defaultProxy;
            }
            return request;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="url"></param>
        /// <param name="retries"></param>
        /// <returns></returns>
        public WebClientResult Download(string url, int retries)
        {
            string lastException = string.Empty;
            int counter = 0;
            while (true)
            {
                try
                {

                    string response = DownloadString(url);
                    return new WebClientResult(response, false);
                }
                catch (WebException webEx)
                {
                    counter++;
                    lastException = ((HttpWebResponse)webEx.Response).StatusCode.ToString();

                    if (((HttpWebResponse)webEx.Response).StatusCode == HttpStatusCode.NotFound)
                    {
                        return new WebClientResult(lastException, true);
                    }
                }
                catch (Exception ex)
                {
                    counter++;
                    lastException = ex.Message;
                }

                if (counter == retries)
                {
                    break;
                }
            }

            return new WebClientResult(lastException, true);
        }
    }
}
