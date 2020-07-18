package com.sim.sign;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class SimSignApplet extends Applet{
	
	private static final byte INS_ECC_GEN_KEYPAIR   =  (byte)0x41;
	private static final byte INS_ECC_GENA          =  (byte)0x42;
	private static final byte INS_ECC_GENP          =  (byte)0x43;
	private static final byte INS_ECC_GENS          =  (byte)0x44;
	private static final byte INS_ECC_GENW          =  (byte)0x45;
	private static final byte INS_ECC_SETS          =  (byte)0x46;
	private static final byte INS_ECC_SETW          =  (byte)0x47;
	private static final byte INS_ECC_SIGN          =  (byte)0x48;
	private static final byte INS_ECC_VERIFY        =  (byte)0x49;
	private static final byte INS_ECC_SIGN_NTIMES   =  (byte)0x4A;
	private static final byte INS_ECC_SIGN_INPUT    =  (byte)0x4B;
	
	private byte[] tempBuffer;
	private byte[] flags;
	private static final short FLAGS_SIZE = (short)5;
	
	private short eccKeyLen;
	private Signature ecdsa;
	private KeyPair eccKey;
	
	private InitializedMessageDigest sha256;
	
	public SimSignApplet(){
		tempBuffer = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);
		flags = JCSystem.makeTransientByteArray(FLAGS_SIZE, JCSystem.CLEAR_ON_DESELECT);
		
		ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		sha256 = MessageDigest.getInitializedMessageDigestInstance(MessageDigest.ALG_SHA_256, false);
		
		JCSystem.requestObjectDeletion();
	}
		    
    public static void install(byte[] bArray, short bOffset, byte bLength) {
		new SimSignApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}
	    
    public void process(APDU apdu){
    	if(selectingApplet()){
	    	return;
    	}
    	
    	byte[] buf = apdu.getBuffer();
    	short len = apdu.setIncomingAndReceive();
    	
    	switch(buf[ISO7816.OFFSET_INS]){
		case INS_ECC_GEN_KEYPAIR:
		    //Gen KeyPair
		    GenEccKeyPair(apdu, len);
		    break;
		case INS_ECC_GENA:
			getEccKeyA(apdu, len);
			break;
		case INS_ECC_GENP:
			getEccKeyP(apdu, len);
			break;
		case INS_ECC_GENS:
			getEccKeyS(apdu, len);
			break;
		case INS_ECC_GENW:
			getEccKeyW(apdu, len);
			break;
	    case INS_ECC_SETS://PrivateKey ECC_SET_S
	        setEccKeyS(apdu, len);
	        break;
	    case INS_ECC_SETW://PublicKey ECC_SET_W
	    	setEccKeyW(apdu, len);
	    	break;
		case INS_ECC_SIGN: //ECC SIGN
			Ecc_Sign(apdu, len);
			break;
		case INS_ECC_VERIFY: //ECC Verify
			Ecc_Verify(apdu, len);
			break;
		case INS_ECC_SIGN_NTIMES:
			Sign_nTimes(apdu, len);
			break;
		case INS_ECC_SIGN_INPUT:
			Sign_InputData(apdu, len);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	    }
    }
    
    // Generate ECC key pair and store in the global variable 'eccKey'
    private void GenEccKeyPair(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    short KeyLen = (short)0;
	    
	    switch(buffer[ISO7816.OFFSET_P1]){
		case (byte)0x01:
			eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_AES_192);
			KeyLen = (short)24;
		case(byte)0x02:
			//eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
			eccKey = new KeyPair(
                        (ECPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
                        (ECPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false));
				
			KeyLen = (short)32;			
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			break;
	    }
	    //Secp256k1.setCommonCurveParameters((ECKey)eccKey.getPrivate());
		//Secp256k1.setCommonCurveParameters((ECKey)eccKey.getPublic());
	     
	    eccKey.genKeyPair();
	    Secp256k1.setCommonCurveParameters((ECKey)eccKey.getPrivate());
		Secp256k1.setCommonCurveParameters((ECKey)eccKey.getPublic());
	    
	    eccKeyLen = KeyLen;
	    
	    /**
	    //Store privateKey to tempBuffer
	    short privateKeyLength = ((ECPrivateKey)eccKey.getPrivate()).getS(tempBuffer, (short)2);
	    Util.setShort(tempBuffer, (short)0, privateKeyLength);
	    
	    //Store publicKey to tempBuffer
	    short publicKeyLength = ((ECPublicKey)eccKey.getPublic()).getW(tempBuffer, (short)130);
	    Util.setShort(tempBuffer, (short)128, publicKeyLength);
	    
	    
	    //Util.arrayCopyNonAtomic(tempBuffer, (short)0, buffer, (short)0, (short)256);
	    //apdu.setOutgoingAndSend((short)0, (short)256);
	    **/
    }
    
    private void getEccKeyA(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    ((ECPrivateKey)eccKey.getPrivate()).getA(buffer, (short)0);
	    apdu.setOutgoingAndSend((short)0, eccKeyLen);
    }
    
    private void getEccKeyP(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    ((ECPrivateKey)eccKey.getPrivate()).getField(buffer, (short)0);
	    apdu.setOutgoingAndSend((short)0, eccKeyLen);
    }
    
    private void getEccKeyS(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    short length = ((ECPrivateKey)eccKey.getPrivate()).getS(buffer, (short)0);
	    apdu.setOutgoingAndSend((short)0, length);
    }
    
    private void getEccKeyW(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    short length = ((ECPublicKey)eccKey.getPublic()).getW(buffer, (short)0);
	    apdu.setOutgoingAndSend((short)0, length);
    }
    
    // PrivateKey
    private void setEccKeyS(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    
	    switch(buffer[ISO7816.OFFSET_P1]){
		case(byte)0x01:
			if(len != 24){
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			eccKeyLen = 24;
			eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_192);
			break;
		case(byte)0x02:
			if(len != 32){
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			eccKeyLen = 32;
			eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			break;
	    }
	    
	    //In tempBuffer, the offset from 0 to 1 positions stored ECC private key, 
	    // including 0 to 0 store the private key length, 130 to 255 store the private key data
	    Util.setShort(tempBuffer, (short)0, len);
	    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short)2, len);
    }
    // Public Key
    private void setEccKeyW(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    
	    switch(buffer[ISO7816.OFFSET_P1]){
		case(byte)0x01:
			if(len != 24*2+1){
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			eccKeyLen = 24;
			eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_AES_192);
			break;
		case(byte)0x02:
			if(len != 32*2+1){
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			}
			eccKeyLen = 32;
			eccKey = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			break;
	    }
	    //In tempBuffer, the offset from 128 to 255 positions stored ECC public key,
	    //  including 128 to 129 stored the public key length, 130 to 255 store the private key data.
	    Util.setShort(tempBuffer, (short)128, len);
	    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short)130, len);
    }
    
    private void Ecc_Sign(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    
	    //(re)initialize the key objects encapsulated in this KeyPair instance with new key values.
	    eccKey.genKeyPair();
	    short eccPriKeyLen = Util.getShort(tempBuffer, (short)0);
	    
	    ((ECPrivateKey)eccKey.getPrivate()).setS(tempBuffer, (short)2, eccPriKeyLen);	    
	    ecdsa.init(eccKey.getPrivate(), Signature.MODE_SIGN);
	    short lenTmp = ecdsa.sign(buffer, ISO7816.OFFSET_CDATA, len, buffer, (short)0);
	    	  	    
	    apdu.setOutgoingAndSend((short)0, lenTmp);    
    } 

    /**
    private static void generateHash(APDU apdu, byte[] buf){
    	byte[] buffer = apdu.getBuffer();
    	
	    InitializedMessageDigest hash = sha256;
	    //hash = sha256;
	    
	    //Resets the MessageDigest object to the initial state for further use.
	    hash.reset();
	    
	    //resultLen = MessageDigest.LENGTH_SHA_256;
	    
	    //byte[] outBuff;
	    //short ret = sha256.doFinal(buf, (short)0, (short)250, outBuff, (short)0);
	    
	    short ret = sha256.doFinal(buf, (short)0, (short)250, buffer, (short)0);
	    apdu.setOutgoingAndSend((short)0, ret);
	    
	    //return ret;
    }
    **/
    
  
    private void Sign_nTimes(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();    
	    //RandomData random = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
	    //short avg_btc_tx_size = (short)8;
	    
	    //(re)initialize the key objects encapsulated in this KeyPair instance with new key values.
	    eccKey.genKeyPair();
	    short eccPriKeyLen = Util.getShort(tempBuffer, (short)0);
	    ((ECPrivateKey)eccKey.getPrivate()).setS(tempBuffer, (short)2, eccPriKeyLen);	    
	    ecdsa.init(eccKey.getPrivate(), Signature.MODE_SIGN);
	    short offset = ISO7816.OFFSET_CDATA;
	    	    
	    //short n = ISO7816.OFFSET_P1;
	    for (short x=0; x<100; x++){	    	
	    	/**	    	
	    	//Gen RandomData
	    	byte[] randomArray = new byte[avg_btc_tx_size];
	    	random.generateData(randomArray, (short)0, avg_btc_tx_size);
	    	//Util.arrayCopy(randomArray, (short)0, buffer, (short)0, avg_btc_tx_size);
            //apdu.setOutgoingAndSend((short)0, avg_btc_tx_size);
            //randomArray = null;
            
		    //Hash(SHA-256)		    
		    InitializedMessageDigest hash = sha256;
		    hash.reset();
		    

		    short hashLen = MessageDigest.LENGTH_SHA_256;
		    byte[] hashBuff = new byte[hashLen];
		    short ret = hash.doFinal(randomArray, (short)0, avg_btc_tx_size, hashBuff, (short)0);
	        //Util.arrayCopy(outBuff, (short)0, buffer, avg_btc_tx_size, ret);
	        //apdu.setOutgoingAndSend((short)0, (short)(avg_btc_tx_size + hashLen));

	        //Hash debug
	        //short ret = hash.doFinal(randomArray, (short)0, avg_btc_tx_size, buffer, (short)0);
	        //apdu.setOutgoingAndSend((short)0, hashLen);
	        **/
		    
		    //Sign
	        byte[] outputBuff = new byte[(short)256];
	        short signLen = ecdsa.sign(buffer, offset, len, outputBuff, (short)0);
	        //apdu.setOutgoingAndSend((short)0, signLen);
	    } 
    }
    
    private void Sign_InputData(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    short offset = ISO7816.OFFSET_CDATA;
	    
	    /**
		// Receive 250byte APDU input. Return the hashed and signed value.
		//Hash
		InitializedMessageDigest hash = sha256;
		short hashLen = MessageDigest.LENGTH_SHA_256;
		byte[] hashBuff = new byte[hashLen];
		hash.doFinal(buffer, offset, len, hashBuff, (short)0);
		
		//Hash(Debug) 
		short hashLen = hash.doFinal(buffer, offset, len, buffer, (short)0);
		apdu.setOutgoingAndSend((short)0, hashLen);
		**/
		
		//Sign
		eccKey.genKeyPair();
	    short eccPriKeyLen = Util.getShort(tempBuffer, (short)0);
	    ((ECPrivateKey)eccKey.getPrivate()).setS(tempBuffer, (short)2, eccPriKeyLen);	    
	    ecdsa.init(eccKey.getPrivate(), Signature.MODE_SIGN);
	    
	    //short signLen = ecdsa.sign(hashBuff, (short)0, hashLen, buffer, (short)0);
	    byte[] outputBuff = new byte[(short)256];
	    short signLen = ecdsa.sign(buffer, offset, len, outputBuff, (short)0);
	    //apdu.setOutgoingAndSend((short)0, signLen);
    }
    
    private void Ecc_Verify(APDU apdu, short len){
	    byte[] buffer = apdu.getBuffer();
	    short signLen = buffer[ISO7816.OFFSET_P1];
	    
	    //(Re)Initialize the key objects encapsulated 
	    //  in 'eccKey' keypair instance with new key values.
	    eccKey.genKeyPair();
	    short eccPubKeyLen = Util.getShort(tempBuffer, (short)128);
	    
	    //Sets the point of the curve compromising the public key.
	    ((ECPublicKey)eccKey.getPublic()).setW(tempBuffer, (short)130, eccPubKeyLen);
	    short plainLen = (short)(len - signLen);
	    short tmpOff = (short)(ISO7816.OFFSET_CDATA + signLen);
	    
	    //Initializes the Signature object with the appropriate key.
	    ecdsa.init(eccKey.getPublic(), Signature.MODE_VERIFY);
	    
	    //Verify the signature of input data against the passed in ECC signature.
	    boolean ret = ecdsa.verify(buffer, (short)tmpOff, plainLen, buffer, ISO7816.OFFSET_CDATA, signLen);
	    buffer[(short)0] = ret ? (byte)1: (byte)0;
	    apdu.setOutgoingAndSend((short)0, (short)1);
    }
}