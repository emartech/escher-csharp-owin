using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading.Tasks;
using EscherAuth.Middlewares.Owin.Request;
using Microsoft.Owin;

namespace EscherAuth.Middlewares.Owin
{
    public class EscherMiddleware
    {
        private readonly Func<IDictionary<string, object>, Task> next;
        private readonly IKeyDb keyDb;
        private readonly Escher escher = new Escher();
        private readonly Action<string> logger;

        public EscherMiddleware(Func<IDictionary<string, object>, Task> next, IKeyDb keyDb) : this(next, keyDb, null, null) { }

        public EscherMiddleware(Func<IDictionary<string, object>, Task> next, IKeyDb keyDb, EscherConfig escherConfig) : this(next, keyDb, escherConfig, null) { }

        public EscherMiddleware(Func<IDictionary<string, object>, Task> next, IKeyDb keyDb, EscherConfig escherConfig, Action<string> logger)
        {
            this.next = next;
            this.keyDb = keyDb;
            this.escher.Config = escherConfig ?? this.escher.Config;
            this.logger = logger ?? (message => Debug.WriteLine(message));
        }

        public async Task Invoke(IDictionary<string, object> env)
        {
            var context = new OwinContext(env);

            try
            {
                var escherKey = escher.Authenticate(new OwinRequestAdapter(context.Request), keyDb);

                logger(string.Format("EscherAuth successful for {0}", escherKey));

                context.Request.User = new GenericPrincipal(new GenericIdentity(escherKey), new string[] { });
            }
            catch (EscherAuthenticationException e)
            {
                logger(string.Format("EscherAuth failed for {0} because {1}", context.Request.Uri, e.Message));
            }

            await next(env);
        }

    }
}
