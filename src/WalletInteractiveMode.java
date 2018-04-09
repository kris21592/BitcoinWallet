import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class WalletInteractiveMode {

	public static Map<String, WalletTransaction> mapWithTransaction = new HashMap<String, WalletTransaction>();
	public static Map<String, Integer> mapWithIndex = new HashMap<String, Integer>();
	public static List<WalletTransaction> listOfTransactions= new ArrayList<WalletTransaction>();
	public static Map<String, Integer> balanceMap = new HashMap<String, Integer>();
	public static Map<String, Integer> changeMap = new HashMap<String, Integer>();
	public static Map<String, String> privatekeyMap = new HashMap<String, String>();

	Scanner sc = new Scanner(System.in);
	Boolean interactiveFlag = false;
	static Boolean verboseFlag = false;
	Boolean isGenesis = false;
	Boolean checkTransaction = false;
	int tempCtr=0;
	int mapIndex = 0;
	static String correctSha1;

	public void displayInteractiveMenu() throws Exception{
		System.out.println("[F]ile");
		System.out.println("[T]ransaction");
		System.out.println("[P]rint");
		System.out.println("[H]elp");
		System.out.println("[D]ump");
		System.out.println("[W]ipe");
		System.out.println("[I]nteractive");
		System.out.println("[V]erbose");
		System.out.println("[B]alance");
		System.out.println("[R]ead Key File");
		System.out.println("[S]ign Transaction");
		System.out.println("[E]xit");

		while(true){
			System.out.println("\nSelect a command: ");
			String input = sc.next().toLowerCase();
			switchMethods(input);
		}
	}

	public void switchMethods(String input) throws Exception
	{
		switch(input){

			case "f":
			case "file":
			{
				if(interactiveFlag)
					System.out.println("Supply Filename: ");
				String filename = sc.next();
				BufferedReader br = null;
				try {
					br = new BufferedReader(new FileReader(filename));
				} catch (FileNotFoundException e) {
					// TODO Auto-generated catch block
					System.err.println("Error: file "+filename+" cannot be opened for reading");
					break;
				}

				String line = null;
				try {
					line = br.readLine();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					System.err.println("Error: While reading "+filename+" file");
					break;
				}

				while(line!=null)
				{
					if(verboseFlag)
						System.out.println("\nTransaction number: "+ ++tempCtr);
					WalletTransaction t = parseTransaction(line);
					updateLedger(t);
					line = br.readLine();
				}
				br.close();
			}
			break;

			case "t":
			case "transaction":
			{
				if(interactiveFlag)
					System.out.println("Supply Transaction: ");
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
				String transaction = br.readLine();
				System.out.println(transaction);
				WalletTransaction t=parseTransaction(transaction);
				updateLedger(t);
			}
			break;

			case "p":
			case "print":
			{
				String p = getTransactionAsString();
				System.out.println(p);
			}
			break;

			case "h":
			case "help":
			{
				help();
			}
			break;

			case "d":
			case "dump":
			{
				BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
				String outputFileName = br.readLine().trim();
				write(getTransactionAsString(), outputFileName);
			}
			break;

			case "w":
			case "wipe":
			{
				wipeLedger();
				if(verboseFlag)
					System.out.println("Ledger has been wiped");
			}
			break;

			case "i":
			case "interactive":
			{
				if(interactiveFlag==false){
					interactiveFlag=true;
					displayInteractiveMenu();
				}
				else{
					interactiveFlag=false;
					nonInteractive();
				}
			}
			break;

			case "v":
			case "verbose":
			{
				verboseFlag = !verboseFlag;
				if(verboseFlag){
					System.out.println("Now in Verbose Mode.");
				}
			}
			break;

			case "b":
			case "balance":
			{
				if(interactiveFlag)
					System.out.println("Enter name: ");
				String n = sc.next();
				if(balanceMap.containsKey(n)){
					System.out.println(n+" has "+balanceMap.get(n));
				}
				else
					System.err.println("Person does not exist!");
			}
			break;

			case "r":
			case "read":
			{
				BufferedReader bread = new BufferedReader(new InputStreamReader(System.in));
				String inputStr[] = null;
				System.out.println("Supply Name and KeyFile Name: ");
				inputStr = bread.readLine().split("\\s+");

				BufferedReader br = null;
				try{
					try {
						br = new BufferedReader(new FileReader(inputStr[1]));
					} catch (FileNotFoundException e) {
						// TODO Auto-generated catch block
						System.err.println("Error: file "+inputStr[1]+" cannot be opened for reading");
						break;
					}
				} catch(ArrayIndexOutOfBoundsException exception) {
					System.err.println("Please enter both name and filename separated by space." + "\n" + exception);
					break;
					}
				String key = "";
				String line = br.readLine();
				while(line!=null){
					key = key+line.replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----", "").replaceAll("\n", "").replaceAll("\r", "");
					line = br.readLine();
				}
				br.close();


				if(privatekeyMap.containsKey(inputStr[0])){
					System.out.println("Key file being overwritten");
					privatekeyMap.put(inputStr[0], key);
				}
				else
					privatekeyMap.put(inputStr[0], key);
			}
			break;

			case "s":
			case "sign":
			{

				System.out.println("Supply input to sign: ");
				String transactionId = sc.next();

				if(!mapWithTransaction.containsKey(transactionId)){
					System.out.println("Error: Transaction not found in ledger!");
					break;
				}

				WalletTransaction t = mapWithTransaction.get(transactionId);
				String signature = null;
				String stringToSign = t.toString().substring(10);

				if(t.m==0){
					if(privatekeyMap.containsKey(t.outputList.get(0).name)){
					//System.out.println("Input: "+stringToSign + "\nSignature: "+signSHA256RSA(t.toString().substring(10), privatekeyMap.get(t.outputList.get(0).name)));
					 try {
						signature = signSHA256RSA(t.toString().substring(10), t.outputList.get(0).name.toLowerCase()+"_private.pem");
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					 System.out.println(t.toString()+System.lineSeparator()+signature);
					}
					else
						System.out.println("Key not present for "+t.outputList.get(0).name);
					}
				else{
					//String signature;
					//System.out.println("old id: "+t.inputList.get(0).oldTransactionId);
					WalletTransaction prev_t = mapWithTransaction.get(t.inputList.get(0).oldTransactionId);
					int ind = t.inputList.get(0).indexOfOutputTx;

					//System.out.println(prev_t.outputList.get(ind).name);
					String name = prev_t.outputList.get(ind).name;
					//String stringToSign = t.toString().substring(10);

					for(int i=1;i<t.m;i++){
						if(prev_t.outputList.get(t.inputList.get(i).indexOfOutputTx).name!=name){
							System.out.println("Invalid Transaction: transaction has multiple accounts that own inputs.");
						}
					}

					try {
						if(privatekeyMap.containsKey(prev_t.outputList.get(ind).name)){
							//System.out.println("Input: "+stringToSign + "\nSignature: "+signSHA256RSA(t.toString().substring(10), privatekeyMap.get(name)));
							 signature = signSHA256RSA(t.toString().substring(10), name.toLowerCase()+"_private.pem");
							 System.out.println(t.toString()+System.lineSeparator()+signature);
						}
						else
							System.out.println("Error: Key not present for "+name);
					} catch (Exception e) {
						// TODO Auto-generated catch block
						System.out.println("Error: transaction not signed");
					}
				}
			}
			break;

			case "e":
			case "exit":
			{
				if(verboseFlag)
					System.out.println("Exiting.. ");
				System.exit(0);
			}
			break;

			default:
			{
				System.out.println("Incorrect option. Please check help for command summary");
			}
		}
	}

	public static String readKeyFile(String filename) throws IOException{
		BufferedReader br = null;
		try {
			br = new BufferedReader(new FileReader(filename));
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			System.err.println("Error: file "+filename+" cannot be opened for reading");
		}
		String key = "";
		String line = br.readLine();
		while(line!=null){
			key = key+line.replaceAll("-----BEGIN PRIVATE KEY-----", "").replaceAll("-----END PRIVATE KEY-----", "").replaceAll("\n", "").replaceAll("\r", "");
			line = br.readLine();
		}
		//System.out.println("private key: "+key);
		return key;
	}

	private static String signSHA256RSA(String data, String filename) throws Exception {

		Signature rsa = Signature.getInstance("SHA256withRSA");
		rsa.initSign(getPrivate(filename));
		rsa.update(data.getBytes());
		byte[] signature = rsa.sign();
		String base64Signature = Base64.getEncoder().encodeToString(signature);
		return base64Signature;
//		byte[] b1 = Base64.getDecoder().decode(strPk);
//		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        Signature privateSignature = Signature.getInstance("SHA256withRSA");
//        privateSignature.initSign(kf.generatePrivate(spec));
//        privateSignature.update(input.getBytes("UTF-8"));
//        byte[] s = privateSignature.sign();
//        return Base64.getEncoder().encodeToString(s);
    }

	public static PrivateKey getPrivate(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		String privateKeyContent = new String(Files.readAllBytes(Paths.get(filename)));
		privateKeyContent = privateKeyContent.replaceAll("\n", "").replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replaceAll("\r", "");
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyContent));
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);
        return privKey;
	}

	private void wipeLedger() {
		// TODO Auto-generated method stub
		mapWithTransaction.clear();
		mapWithIndex.clear();
		listOfTransactions.clear();
		balanceMap.clear();
		changeMap.clear();
		resetFlags();
	}

	private void resetFlags() {
		// TODO Auto-generated method stub
		interactiveFlag = false;
		verboseFlag = false;
		isGenesis = false;
		checkTransaction = false;
		tempCtr=0;
		mapIndex = 0;
	}

	private void help() {
		// TODO Auto-generated method stub
		System.out.println("List of commands: \n");
		System.out.println("1. File\nCommand[F/f/file]\nInput Required[input filename]\nWill read in transactions from a file and add it to the ledger if successfully validated.\n");
		System.out.println("2. Transaction\nCommand[T/t/transaction]\nInput Required[transaction in the format shown below]\nWill take in the transaction given as input and validate it against the ledger and add if successfully validated.\n");
		System.out.println("Format of Transactions:\n<TransID>; M; (<TransID>, <vout>)^M; N; (<AcctID>, <amount>)^N\nItems in angle brackets are parameters, M and N are whole numbers, and caret M (or N) indicates M (or N) repetitions of the parenthesized pairs.");
		System.out.println("\nExample Transaction:\n4787df35; 1; (f2cea539, 0); 3; (Bob, 150)(Alice, 845)(Gopesh, 5)\n");
		System.out.println("3. Print\nCommands[P/p/print], Prints the ledger on the screen\n");
		System.out.println("4. Help\nCommands[H/h/help]\nOpens summary of commands.\n");
		System.out.println("5. Dump\nCommands[D/d/dump]\nInput Required[output filename]\nDumps the contents of the ledger into the output file.\n");
		System.out.println("6. Wipe\nCommands[W/w/wipe]\nWill wipe the ledger clean.\n");
		System.out.println("7. Interactive\nCommands[I/i/interactive]\nToggle between interactive and non interactive modes.\n");
		System.out.println("8. Verbose\nCommands[V/v/verbose]\nToggle between verbose and non verbose modes.\n");
		System.out.println("9. Balance\nCommands[B/b/balance], Input Required[account id]\nDisplay balance of the account id entered.\n");
		System.out.println("10. Exit\nCommands[E/e/exit]\nExit the program");
	}

	public String getTransactionAsString(){
		StringBuilder sb = new StringBuilder();
		for(WalletTransaction t: listOfTransactions){
			sb.append(t.toString()).append(System.lineSeparator());
		}
		return sb.toString();
	}

	void nonInteractive() throws Exception {
		// TODO Auto-generated method stub
		while(true){
			String s = sc.next().toLowerCase();
			switchMethods(s);}
	}

	public void updateLedger(WalletTransaction t){
		if(t.m==0){
			isGenesis = true;
			mapWithTransaction.put(t.transactionId, t);
			mapWithIndex.put(t.transactionId, mapIndex);
			listOfTransactions.add(t);
			mapIndex++;
			for(WalletOutputTransaction o: t.outputList)
			{
				balanceMap.put(o.name, o.amount);
				changeMap.put(o.name, o.amount);
				//System.out.println("Balance for: "+o.name+" is: "+o.amount);
			}
			System.out.println(t.transactionId+": good");
		}
		else
		{
			checkTransaction = validateTransaction(t);
			if(!correctSha1.equals(t.transactionId)){
				t.transactionId=correctSha1;
			}
			if(checkTransaction == true){
				listOfTransactions.add(t);
				System.out.println(t.transactionId+": good");
				if(verboseFlag)
					System.out.println("Adding transaction to ledger.. ");

				mapWithTransaction.put(t.transactionId, t);
				mapWithIndex.put(t.transactionId, mapIndex);
				mapIndex++;

				for(WalletOutputTransaction o: t.outputList)
				{
					if(changeMap.containsKey(o.name))
						balanceMap.put(o.name,changeMap.get(o.name));
					else
						balanceMap.put(o.name, o.amount);
				}
			}
			else{
				System.out.println(t.transactionId+": bad");
				//System.out.println("Invalid Transaction! ");
			}
		}
	}

	public WalletTransaction parseTransaction(String line){
		String trans[] = null;
		String t1[] = null;
		String t2[] = null;
		String t3[] = null;
		String t4[] = null;
		String name, txId, oldTxId;
		int m = 0,n,opTx,ipTx,amt;
		while(line!=null){
			WalletTransaction transaction = new WalletTransaction();
			WalletInputTransaction in = new WalletInputTransaction();
			WalletOutputTransaction out = new WalletOutputTransaction();
			List<WalletInputTransaction> l1 = new ArrayList<WalletInputTransaction>();
			List<WalletOutputTransaction> l2 = new ArrayList<WalletOutputTransaction>();
			line=line.replaceAll("\\s", "");
			if(line.charAt(8) == ';'){
				trans = line.split(";");
				m = Integer.parseInt(trans[1]);
				if(m==0){
					if(isGenesis == true){
						System.err.println("Error! Genesis transaction already exists!");
					}
					else{
						WalletTransaction t = new WalletTransaction();
						txId = trans[0];
						t.setTransactionId(txId);
						n = Integer.parseInt(trans[3]);
						t.setM(m);
						t.setN(n);
						t1 = trans[2].split("\\)");
						t3 = trans[4].split("\\)");

						for(int index = 0; index<t3.length; index++){
							out = new WalletOutputTransaction();
							t4 =t3[index].split(",");
							name = t4[0].replaceAll("\\(", "");
							out.setName(name);
							amt = Integer.parseInt(t4[1]);
							out.setAmount(amt);
							l2.add(out);
						}
						t.setOutputList(l2);
						return t;
					}
				}
				else{
						if(isGenesis == false)
						{
							System.err.println("Error: Genesis transaction required. ");
						}
						else
						{
							WalletTransaction t = new WalletTransaction();
							//Parsing from second line
							txId = trans[0];
							t.setTransactionId(txId);
							t.setM(m);
							t1 = trans[2].split("\\)");
							for(int index = 0; index<t1.length; index++){
								in = new WalletInputTransaction();
								t2 = t1[index].split(",");
								oldTxId = t2[0].replaceAll("\\(", "");
								in.setOldTransactionId(oldTxId);
								opTx = Integer.parseInt(t2[1]);
								in.setIndexOfOutputTx(opTx);
								l1.add(in);
							}
							t.setInputList(l1);
							n = Integer.parseInt(trans[3]);
							t.setN(n);
							t3 = trans[4].split("\\)");
							for(int index = 0; index<t3.length; index++){
								out = new WalletOutputTransaction();
								t4 =t3[index].split(",");
								name = t4[0].replaceAll("\\(", "");
								out.setName(name);
								amt = Integer.parseInt(t4[1]);
								out.setAmount(amt);
								l2.add(out);
							}
							t.outputList = l2;
							return t;
						}
					}
				}
			else
			{
				System.err.println("Error: Format of the transaction is incorrect!");
				break;
			}
			}
		return null;
	}

	public static boolean validateTransaction(WalletTransaction t){
		changeMap.clear();
		int m = t.getM();
		int n = t.getN();
		String inputName = null;
		int inputSum=0;
		int outputSum=0;
		int inputAmt;
		int change=0;
		String txId = t.getTransactionId();
		WalletTransaction old = null;
		int indexOfOldTx;
		List<String> tempSet = new ArrayList<String>();
		//System.out.println("m: "+m+" n: "+n+" tId: " + txId);

		if(m==t.inputList.size()){
			for(int index = 0;index<m;index++){
				//System.out.println("M Index: "+index);
				String oldTxId = t.inputList.get(index).oldTransactionId;
				//System.out.println("Old tx id: "+oldTxId);


				if(!mapWithIndex.containsKey(oldTxId)){
					System.err.println(t.transactionId+": Error! Linked Old Transaction ID not found in ledger");
					return false;
				}
				else{
					indexOfOldTx = mapWithIndex.get(oldTxId);
					old = listOfTransactions.get(indexOfOldTx);
					//System.out.println("index of old tx: "+indexOfOldTx);

					inputAmt = old.outputList.get(t.inputList.get(index).indexOfOutputTx).amount;
					inputName = old.outputList.get(t.inputList.get(index).indexOfOutputTx).name;
					//System.out.println("INPUT NAME: "+inputName);
					//System.out.println("INPUT AMT: "+inputAmt);

					if(index == 0){
						tempSet.add(inputName);
					}

					if(index>0){
						if(!tempSet.contains(inputName)){
							System.out.println(t.transactionId+": Invalid Transaction: transaction has multiple accounts that own inputs.");
							return false;

						}
					}
					if(balanceMap.get(inputName) >= inputAmt)
					{
						inputSum+=inputAmt;
						//System.out.println("input sum: "+ inputSum + " old input amt: "+inputAmt);

						change = balanceMap.get(inputName) - inputSum;
						changeMap.put(inputName, change);
						//System.out.println("Change: "+change);
					}
					else{
						System.err.println(t.transactionId+": Error! account does not have enough Balance! ");
					}
				}
			}
			if(n==t.outputList.size()){
				for(int index = 0;index<n;index++){
					//System.out.println("here in N");
					if(!(changeMap.containsKey(t.outputList.get(index).name)))
					{
						if(!t.outputList.get(index).name.equals(inputName)){
							//System.out.println("OUTPUT NAME: "+t.outputList.get(index).name+" INPUT NAME: "+inputName+" Balance of output NAME: "+ balanceMap.get(t.outputList.get(index).name)+" CURR AMT: "+t.outputList.get(index).amount);
							if(balanceMap.containsKey(t.outputList.get(index).name))
								changeMap.put(t.outputList.get(index).name, t.outputList.get(index).amount+balanceMap.get(t.outputList.get(index).name));
						}
						else
							changeMap.put(t.outputList.get(index).name, t.outputList.get(index).amount);
					}
					else
					{
						changeMap.put(t.outputList.get(index).name, changeMap.get(t.outputList.get(index).name)+t.outputList.get(index).amount);
					}
					outputSum+=t.outputList.get(index).amount;
				}
			}
			else
			{
				System.err.println(t.transactionId+": Error! The value of n does not equal the no of output pairs");
			}
		}
		else
		{
			System.err.println(t.transactionId+": Error! The value of m does not equal the no of input pairs");
		}

		//System.out.println("Input sum " + inputSum + " Output sum: " + outputSum);
		if(inputSum==outputSum){
			if(!validateSha1(txId, correctSha1 = generateHash(t.toString().substring(10)))){
				System.err.println(t.transactionId+": has failed sha1 validation. Changing transaction id to: " + correctSha1);
			}
			return true;
		}

		else
		{
			System.err.println(t.transactionId+": Input Sum does not match output sum");
			return false;
		}
	}

	private void write(String Transactions, String outputFileName) throws IOException {
		//System.out.println(Transactions);
		File f = new File(outputFileName);
		if (!f.exists() || !f.canWrite())
			System.err.println("Error: file " + outputFileName + " cannot be opened for writing!!!");

		FileWriter fw = new FileWriter(f);
		BufferedWriter br = new BufferedWriter(fw);

		try {
			br.write(Transactions);
		} catch (IOException e) {
			System.err.println("Error: file " + outputFileName + " cannot be opened for writing");
		}finally{
			br.flush();
			br.close();
		}
	}

	public static boolean validateSha1(String txId, String sha1) {
		//System.out.println("Sha1 ID: " +sha1+ " TxID: "+txId);
		if(txId.equals(sha1))
			return true;
		else
			return false;
	}

	private static String generateHash(String string)
	{
	    String _sha1 = "";
	    string += "\n";
	    try{
	        MessageDigest md = MessageDigest.getInstance("SHA-1");
	        md.reset();
	        md.update(string.getBytes("UTF-8"));
	        _sha1 = convertBytestoHex(md.digest());
	    }
	    catch(NoSuchAlgorithmException e){
	        e.printStackTrace();
	    }
	    catch(UnsupportedEncodingException e){
	        e.printStackTrace();
	    }
	    return _sha1.substring(0, 8);
	}

	private static String convertBytestoHex(final byte[] byteArray){
	    Formatter formatter = new Formatter();
	    for (byte b : byteArray){
	        formatter.format("%02x", b);
	    }
	    String result = formatter.toString();
	    formatter.close();
	    return result;
	}
}
