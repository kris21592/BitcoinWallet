import java.util.ArrayList;
import java.util.List;

public class WalletTransaction {

	String transactionId;
	int m;
	List<WalletInputTransaction> inputList = new ArrayList<WalletInputTransaction>();
	int n;
	List<WalletOutputTransaction> outputList = new ArrayList<WalletOutputTransaction>();


	public WalletTransaction(String transactionId, int m, List<WalletInputTransaction> inputList, int n,
			List<WalletOutputTransaction> outputList) {
		super();
		this.transactionId = transactionId;
		this.m = m;
		this.inputList = inputList;
		this.n = n;
		this.outputList = outputList;
	}
	public WalletTransaction() {
		// TODO Auto-generated constructor stub
		super();
	}
	public String getTransactionId() {
		return transactionId;
	}
	public void setTransactionId(String transactionId) {
		this.transactionId = transactionId;
	}
	public int getM() {
		return m;
	}
	public void setM(int m) {
		this.m = m;
	}
	public int getN() {
		return n;
	}
	public void setN(int n) {
		this.n = n;
	}
	public List<WalletInputTransaction> getInputList() {
		return inputList;
	}
	public void setInputList(List<WalletInputTransaction> inputList) {
		this.inputList = inputList;
	}
	public List<WalletOutputTransaction> getOutputList() {
		return outputList;
	}
	public void setOutputList(List<WalletOutputTransaction> outputList) {
		this.outputList = outputList;
	}

	public String toString(){
		String result;
		result = this.transactionId + "; " + this.m + "; ";
		if(this.m > 0) {
			if(this.inputList!=null) {
				for(WalletInputTransaction in : this.inputList) {
					if(in.oldTransactionId!=null && in.indexOfOutputTx>-1) {
						result = result + "("+in.oldTransactionId+", " + in.indexOfOutputTx + ")";
					}
				}
			}
		}
		result+="; " +this.n+ "; ";

		for (WalletOutputTransaction out : this.outputList) {
			result += "(" + out.name + ", " + out.amount + ")";
		}
		return result;
	}
}
