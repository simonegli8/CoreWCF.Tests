﻿#pragma checksum "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "8083efee391f8864468145b9ff50f5ffa1bd6732"
// <auto-generated/>
#pragma warning disable 1591
namespace SolidCP.Build
{
    #line hidden
#nullable restore
#line 2 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
using Microsoft.CodeAnalysis;

#line default
#line hidden
#nullable disable
#nullable restore
#line 3 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
using Microsoft.CodeAnalysis.CSharp;

#line default
#line hidden
#nullable disable
#nullable restore
#line 4 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
using Microsoft.CodeAnalysis.CSharp.Syntax;

#line default
#line hidden
#nullable disable
#nullable restore
#line 5 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
using System.Collections.Generic;

#line default
#line hidden
#nullable disable
#nullable restore
#line 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
using System.Linq;

#line default
#line hidden
#nullable disable
#nullable restore
#line 8 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
using static Microsoft.CodeAnalysis.CSharp.SyntaxFactory;

#line default
#line hidden
#nullable disable
    #nullable restore
    internal partial class ServiceInterface : RazorBlade.PlainTextTemplate
    #nullable disable
    {
        #pragma warning disable 1998
        protected async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("// wcf service contract\r\n");
            WriteLiteral("\r\n");
            WriteLiteral("\r\n");
            WriteLiteral("\r\n");
#nullable restore
#line (13,2)-(13,22) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
Write(Class.AttributeLists);

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n[System.CodeDom.Compiler.GeneratedCodeAttribute(\"SolidCP.Build\", \"1.0\")]\r\n[ServiceContract(Namespace=\"");
#nullable restore
#line (15,31)-(15,50) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
Write(WebServiceNamespace);

#line default
#line hidden
#nullable disable
            WriteLiteral("\")]\r\npublic interface I");
#nullable restore
#line (16,21)-(16,37) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
Write(Class.Identifier);

#line default
#line hidden
#nullable disable
            WriteLiteral(" {\r\n\r\n");
#nullable restore
#line 18 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
     foreach (var method in WebMethods
		.Select(m => (MemberDeclarationSyntax)MethodDeclaration(m.ReturnType, m.Identifier)
					.WithAttributeLists(m.AttributeLists
						.Add(AttributeList(SingletonSeparatedList(Attribute(IdentifierName("OperationContract"))))))
					.WithParameterList(m.ParameterList)
					.WithSemicolonToken(Token(SyntaxKind.SemicolonToken)))) {
		

#line default
#line hidden
#nullable disable
#nullable restore
#line (24,4)-(24,10) 6 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
Write(method);

#line default
#line hidden
#nullable disable
#nullable restore
#line 24 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
               
	}

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n}\r\n\r\n");
        }
        #pragma warning restore 1998
#nullable restore
#line 30 "C:\GitHub\CoreWCF.Tests\SolidCP\SolidCP.Build\ServiceInterface.cshtml"
 
	public string WebServiceNamespace { get; set; }
	public ClassDeclarationSyntax Class { get; set; }
	public IEnumerable<MethodDeclarationSyntax> WebMethods { get; set; }

#line default
#line hidden
#nullable disable
    }
}
#pragma warning restore 1591