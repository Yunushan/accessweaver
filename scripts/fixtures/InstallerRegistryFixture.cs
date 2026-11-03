using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

// Disposable hosted fixture only. Preserve the complete owned key while hiding
// the 64-bit view; never copy/delete its values or change a shared parent ACL.
public static class InstallerRegistryFixture
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int RegRenameKey(SafeRegistryHandle key, string subKey, string newName);

    public static void Rename(RegistryKey parent, string oldName, string newName)
    {
        if (parent == null || String.IsNullOrEmpty(oldName) || String.IsNullOrEmpty(newName) ||
            oldName.IndexOf('\\') >= 0 || newName.IndexOf('\\') >= 0)
            throw new ArgumentException("Expected one owned registry leaf");
        int status = RegRenameKey(parent.Handle, oldName, newName);
        if (status != 0) throw new Win32Exception(status);
    }
}
