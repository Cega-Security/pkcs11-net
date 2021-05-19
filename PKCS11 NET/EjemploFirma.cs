using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using System;
using System.Collections.Generic;

namespace PKCS11_NET
{
    class EjemploFirma
    {
        static void Main(string[] args)
        {
            //Contraseña para el usuario criptográfico
            string NormalUserPin = @"pass";
            //Nombre de la llave
            string KeyLabel = @"key_RSA_PKCS11";
            // Ruta de la librería del PKCS#11 de Utimaco
            string pkcs11LibraryPath = @"..\lib\cs_pkcs11_R2.dll";

            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            // Cargar la librería
            using (IPkcs11Library pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, pkcs11LibraryPath, AppType.SingleThreaded, InitType.WithFunctionList))
            {
                //Mostrar información sobre la librería para verificar que se carga correctamente, esta sección no es necesaria para la firma
                ILibraryInfo libraryInfo = pkcs11Library.GetInfo();
                Console.WriteLine("Library");
                Console.WriteLine("  Manufacturer:       " + libraryInfo.ManufacturerId);
                Console.WriteLine("  Description:        " + libraryInfo.LibraryDescription);
                Console.WriteLine("  Version:            " + libraryInfo.LibraryVersion);

                //Cargar el slot que se configuró con el programa
                ISlot slot = pkcs11Library.GetSlotList(SlotsType.WithTokenPresent)[0];
                using (ISession session = slot.OpenSession(SessionType.ReadOnly))
                {
                    // Login
                    session.Login(CKU.CKU_USER, NormalUserPin);
                    Console.WriteLine("User logged in");

                    byte[] signature = null;
                    IObjectHandle privateKey = null;
                    IObjectHandle publicKey = null;

                    //Firma con la llave privada
                    List<IObjectAttribute> objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, KeyLabel));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY));

                    List<IObjectHandle> foundObjects = session.FindAllObjects(objectAttributes);
                    if (foundObjects.Count > 0)
                    {
                        Console.WriteLine("Private Key found: " + KeyLabel);
                        privateKey = foundObjects[0];

                        IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);
                        byte[] sourceData = ConvertUtils.Utf8StringToBytes("Cega Security");
                        Console.WriteLine("Sign");
                        signature = session.Sign(mechanism, privateKey, sourceData);
                        Console.WriteLine("Sign: " + Convert.ToBase64String(signature));
                    }
                    else
                        Console.WriteLine("Public key not found");

                    //Verificación de la firma con la llave pública
                    objectAttributes = new List<IObjectAttribute>();
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, KeyLabel));
                    objectAttributes.Add(session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY));

                    foundObjects = session.FindAllObjects(objectAttributes);
                    if (foundObjects.Count > 0)
                    {
                        Console.WriteLine("Public Key found: " + KeyLabel);
                        publicKey = foundObjects[0];

                        IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_SHA256_RSA_PKCS);
                        byte[] originalData = ConvertUtils.Utf8StringToBytes("Cega Security");
                        byte[] fakeData = ConvertUtils.Utf8StringToBytes("Cega Security fake");

                        bool isValid = false;
                        Console.WriteLine("Verify");
                        session.Verify(mechanism, publicKey, originalData, signature, out isValid);
                        Console.WriteLine(ConvertUtils.BytesToUtf8String(originalData) + " valido " + isValid);
                        session.Verify(mechanism, publicKey, fakeData, signature, out isValid);
                        Console.WriteLine(ConvertUtils.BytesToUtf8String(fakeData) + " valido " + isValid);
                    }
                    else
                        Console.WriteLine("Public key not found");

                    session.Logout();
                }

            }

            Console.WriteLine("Finish");
            Console.ReadLine();
        }
    }
}
