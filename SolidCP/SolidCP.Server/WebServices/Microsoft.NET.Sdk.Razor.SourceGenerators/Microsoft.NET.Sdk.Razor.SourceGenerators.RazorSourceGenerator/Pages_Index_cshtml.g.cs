﻿#pragma checksum "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml" "{8829d00f-11b8-4213-878b-770e8597ac16}" "df477f7a015d844600cbd6b57131acd768bf207cef4885222d879acffde77766"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCoreGeneratedDocument.Pages_Index), @"mvc.1.0.razor-page", @"/Pages/Index.cshtml")]
namespace AspNetCoreGeneratedDocument
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 2 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
using System.Reflection;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemMetadataAttribute("RouteTemplate", "/")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemMetadataAttribute("Identifier", "/Pages/Index.cshtml")]
    [global::System.Runtime.CompilerServices.CreateNewOnMetadataUpdateAttribute]
    #nullable restore
    internal sealed class Pages_Index : global::Microsoft.AspNetCore.Mvc.RazorPages.Page
    #nullable disable
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("id", new global::Microsoft.AspNetCore.Html.HtmlString("Head1"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_1 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("runat", new global::Microsoft.AspNetCore.Html.HtmlString("server"), global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        #pragma warning restore 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.HeadTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper;
        private global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.BodyTagHelper __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n");
            WriteLiteral("\r\n");
#nullable restore
#line 10 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
  
    // set version
    object[] attrs = Assembly.GetExecutingAssembly().GetCustomAttributes(typeof(AssemblyFileVersionAttribute), true);
    if(attrs.Length > 0)
        Version = ((AssemblyFileVersionAttribute)attrs[0]).Version;

    // asp.net mode
    Bitness = (IntPtr.Size == 8) ? "64-bit" : "32-bit";

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\r\n<html xmlns=\"http://www.w3.org/1999/xhtml\">\r\n");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("head", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "df477f7a015d844600cbd6b57131acd768bf207cef4885222d879acffde777664485", async() => {
                WriteLiteral(@"
    <title>SolidCP Server</title>
    <style>
        BODY {
            margin: 0px;
            padding: 10px;
            font-family: Tahoma, Arial;
            font-size: 10pt;
        }

        .Content {
            width: 400px;
            margin-top: 30px;
            margin-left: auto;
            margin-right: auto;
            text-align: center;
        }

        H1 {
            font-family: Arial, Tahoma;
            font-size: 18pt;
            margin-top: 40px;
            margin-bottom: 5px;
            font-weight: bold;
            padding: 4px;
        }

        TABLE {
            background-color: #e0e0e0;
            padding: 4px;
        }

        TD {
            padding: 8px;
            background-color: #ffffff;
        }

        .FieldName {
            width: 100px;
            font-weight: bold;
        }
    </style>
");
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.HeadTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_HeadTagHelper);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_0);
            __tagHelperExecutionContext.AddHtmlAttribute(__tagHelperAttribute_1);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("\r\n");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("body", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.StartTagAndEndTag, "df477f7a015d844600cbd6b57131acd768bf207cef4885222d879acffde777666549", async() => {
                WriteLiteral(@"
    <form id=""AspForm"" runat=""server"">
        <div class=""Content"">
            <div>
                <img src=""img/logo.png"" />
            </div>

            <h1>Server</h1>

            <table cellpadding=""0"" cellspacing=""1"" align=""center"">
                <tr>
                    <td class=""FieldName"">Status:</td>
                    <td>Running</td>
                </tr>
                <tr>
                    <td class=""FieldName"">Version:</td>
                    <td>");
#nullable restore
#line (81,26)-(81,33) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
Write(Version);

#line default
#line hidden
#nullable disable
                WriteLiteral("</td>\r\n                </tr>\r\n                <tr>\r\n                    <td class=\"FieldName\">URL:</td>\r\n                    <td>");
#nullable restore
#line (85,27)-(85,53) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
Write(HttpContext.Request.Scheme);

#line default
#line hidden
#nullable disable
                WriteLiteral("://");
#nullable restore
#line (85,59)-(85,83) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
Write(HttpContext.Request.Host);

#line default
#line hidden
#nullable disable
#nullable restore
#line (85,86)-(85,110) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
Write(HttpContext.Request.Path);

#line default
#line hidden
#nullable disable
                WriteLiteral("</td>\r\n                </tr>\r\n                <tr>\r\n                    <td class=\"FieldName\">ASP.NET Mode:</td>\r\n                    <td>");
#nullable restore
#line (89,26)-(89,33) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
Write(Bitness);

#line default
#line hidden
#nullable disable
                WriteLiteral("</td>\r\n                </tr>\r\n            </table>\r\n            <br /><br />\r\n            <a href=\"https://solidcp.com\">SolidCP</a> &COPY; Copyright ");
#nullable restore
#line (93,73)-(93,90) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
Write(DateTime.Now.Year);

#line default
#line hidden
#nullable disable
                WriteLiteral(" All Rights Reserved.\r\n        </div>\r\n    </form>\r\n");
            }
            );
            __Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.Razor.TagHelpers.BodyTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_Razor_TagHelpers_BodyTagHelper);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("\r\n</html>\r\n");
        }
        #pragma warning restore 1998
#nullable restore
#line 4 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Server\Pages\Index.cshtml"
            
    string Version {get; set; }
    string Bitness { get; set; }
    //string Url { get; set; }

#line default
#line hidden
#nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; } = default!;
        #nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; } = default!;
        #nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; } = default!;
        #nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; } = default!;
        #nullable disable
        #nullable restore
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<Pages_Index> Html { get; private set; } = default!;
        #nullable disable
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary<Pages_Index> ViewData => (global::Microsoft.AspNetCore.Mvc.ViewFeatures.ViewDataDictionary<Pages_Index>)PageContext?.ViewData;
        public Pages_Index Model => ViewData.Model;
    }
}
#pragma warning restore 1591