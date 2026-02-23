// Manual reconstruction of small linked-list helper routines from GHIDRA snapshot.

class NodeScanner {
public:
  unsigned int pad_00;
  unsigned int pad_04;
  unsigned int pad_08;
  unsigned int pad_0c;
  NodeScanner *next;

  unsigned int ScanLinkedListForNodeByNextPointer(void *target_node);
};

// GHIDRA comment: traverses forward-linked nodes via +0x10 next pointer.
// FUNCTION: IMPERIALISM 0x00607077
unsigned int NodeScanner::ScanLinkedListForNodeByNextPointer(void *target_node)
{
  NodeScanner *cur = this;
  while (cur != 0) {
    if (cur == target_node) {
      return 1;
    }
    cur = cur->next;
  }
  return 0;
}

class LinkedListQueryOwner {
public:
  virtual NodeScanner *GetNodeScanner();

  int IsNodePresentInLinkedListByNextPointer(int target);
};

// FUNCTION: IMPERIALISM 0x00606fc0
int LinkedListQueryOwner::IsNodePresentInLinkedListByNextPointer(int target)
{
  NodeScanner *scanner = GetNodeScanner();
  return scanner->ScanLinkedListForNodeByNextPointer(reinterpret_cast<void *>(target));
}

// FUNCTION: IMPERIALISM 0x00606fd2
int ReturnNodeIfPresentInLinkedListByNextPointer(int node, int owner)
{
  return (owner != 0 &&
          ((LinkedListQueryOwner *)owner)->IsNodePresentInLinkedListByNextPointer(node) != 0)
             ? owner
             : 0;
}
