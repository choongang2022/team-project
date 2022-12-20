package com.oracle.choongangGroup.dongho.admin;

import java.util.ArrayList;
import java.util.List;

public interface AdminService {

	List<MemberPagingDto> memberPaging(int pageNum);

	int memberCount();

	int deleteMember(ArrayList<String> deleteIdList);

}
