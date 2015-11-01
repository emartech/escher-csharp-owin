using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using EscherAuth.Request;
using Microsoft.Owin;

namespace EscherAuth.Middlewares.Owin.Request
{

    class OwinRequestAdapter : IEscherRequest
    {
        private readonly IOwinRequest request;
        private string bodyCache = null;

        public OwinRequestAdapter(IOwinRequest request)
        {
            this.request = request;
            this.Headers = request.Headers.SelectMany(h => h.Value.Select(v => new Header(h.Key, v))).ToList();
        }

        public string Method => request.Method;
        public Uri Uri => request.Uri;
        public List<Header> Headers { get; }
        public string Body
        {
            get
            {
                if (bodyCache != null)
                {
                    return bodyCache;
                }

                using (var reader = new StreamReader(request.Body))
                {
                    var bodyAsString = reader.ReadToEnd();
                    bodyCache = bodyAsString;
                    request.Body = new MemoryStream(Encoding.UTF8.GetBytes(bodyAsString));
                }

                return bodyCache;
            }
        }
    }

}
